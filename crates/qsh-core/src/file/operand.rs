//! The operand grammar of `qsh cp` (`docs/adr/0029-file-copy.md` decision 2,
//! `docs/CLI.md` §6.21): which operand is remote, and so whether a call is a
//! put or a get.
//!
//! Pure string work: nothing here touches the filesystem, the trust store or
//! the network, so a malformed command line is refused before anything
//! exists (decision 17: `INVALID_ARGUMENT`, exit `2`).
//!
//! The Windows client's drive-letter rule (a `:` one character in is a drive,
//! not a host) takes effect with ADR-0035 decision 1 (M19); until then every
//! build reads `C:\x` as host `C`.

use qsh_proto::FileCopyReq;

/// A malformed `qsh cp` operand list. Always `INVALID_ARGUMENT`; the CLI
/// answers it with exit `2` before the copy starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperandError {
    /// What is wrong, for the person at the keyboard.
    pub message: String,
}

impl OperandError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for OperandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for OperandError {}

/// The remote half of an operand: `[user@]host:path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteOperand {
    /// The `user@` assertion, if given.
    pub user: Option<String>,
    /// The host name as typed (brackets of an IPv6 literal removed).
    pub host: String,
    /// The text after the colon, exactly as typed. Empty means the account's
    /// home directory ([`Self::wire_path`] turns it into `~`).
    pub path: String,
}

impl RemoteOperand {
    /// The path as it goes on the wire: `host:` is `~` (decision 2).
    pub fn wire_path(&self) -> String {
        wire_path(&self.path)
    }
}

/// The wire form of a remote path as typed: an empty one is the home
/// directory.
pub fn wire_path(path: &str) -> String {
    if path.is_empty() {
        "~".to_string()
    } else {
        path.to_string()
    }
}

/// One parsed operand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operand {
    /// A path on this machine, as typed.
    Local(String),
    /// A path on a qsh host.
    Remote(RemoteOperand),
}

/// Which way a call copies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Host to this machine.
    Get,
    /// This machine to the host.
    Put,
}

impl Direction {
    /// `get` or `put`, the JSON `direction`.
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Get => "get",
            Direction::Put => "put",
        }
    }
}

/// What a valid operand list means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyPlan {
    /// Put or get.
    pub direction: Direction,
    /// The one host every remote operand names.
    pub host: String,
    /// The `user@` assertion every remote operand agrees on, if any.
    pub user: Option<String>,
    /// The source operands. Local paths as typed for a put, wire paths
    /// (`~` for `host:`) for a get.
    pub sources: Vec<String>,
    /// The destination. A wire path for a put, a local path as typed for a
    /// get.
    pub destination: String,
}

/// Read one operand.
///
/// An operand is remote when a `:` comes before the first `/` and the host
/// part before it is not empty (`host:path`, `user@host:path`,
/// `[::1]:path`); `./a:b` is a local file. `-` (stdin/stdout) is refused.
pub fn parse_operand(operand: &str) -> Result<Operand, OperandError> {
    if operand == "-" {
        return Err(OperandError::new(
            "`-` (stdin/stdout) is not supported by qsh cp",
        ));
    }
    if operand.is_empty() {
        return Err(OperandError::new("empty operand"));
    }
    let head_end = operand.find('/').unwrap_or(operand.len());
    let head = &operand[..head_end];

    // `[user@][v6]:path`. The colons inside the brackets are not the
    // separator, so this is read before the plain form.
    let bracket = match head.find('[') {
        Some(0) => Some((None, 0)),
        Some(open) if head[..open].ends_with('@') => Some((Some(&head[..open - 1]), open)),
        _ => None,
    };
    if let Some((user, open)) = bracket {
        // `[` without a closing `]:` is just an odd local file name.
        let Some(close) = operand[open..].find(']').map(|i| open + i) else {
            return Ok(Operand::Local(operand.to_string()));
        };
        if operand.as_bytes().get(close + 1) != Some(&b':') || close + 1 > head_end {
            return Ok(Operand::Local(operand.to_string()));
        }
        let host = &operand[open + 1..close];
        if host.is_empty() {
            return Err(OperandError::new(format!("empty host in {operand:?}")));
        }
        return Ok(Operand::Remote(RemoteOperand {
            user: user_part(user, operand)?,
            host: host.to_string(),
            path: operand[close + 2..].to_string(),
        }));
    }

    let Some(colon) = head.find(':') else {
        return Ok(Operand::Local(operand.to_string()));
    };
    let target = &operand[..colon];
    let (user, host) = match target.rsplit_once('@') {
        Some((user, host)) => (Some(user), host),
        None => (None, target),
    };
    if host.is_empty() {
        // `:x` has no host: not a remote operand.
        return Ok(Operand::Local(operand.to_string()));
    }
    Ok(Operand::Remote(RemoteOperand {
        user: user_part(user, operand)?,
        host: host.to_string(),
        path: operand[colon + 1..].to_string(),
    }))
}

fn user_part(user: Option<&str>, operand: &str) -> Result<Option<String>, OperandError> {
    match user {
        Some("") => Err(OperandError::new(format!("empty user in {operand:?}"))),
        Some(user) => Ok(Some(user.to_string())),
        None => Ok(None),
    }
}

/// Decide what an operand list means (decision 2). Every refusal is
/// `INVALID_ARGUMENT` and happens before anything is opened.
pub fn plan(req: &FileCopyReq) -> Result<CopyPlan, OperandError> {
    if req.sources.is_empty() {
        return Err(OperandError::new(
            "expected at least one source and a destination",
        ));
    }
    let sources = req
        .sources
        .iter()
        .map(|s| parse_operand(s))
        .collect::<Result<Vec<_>, _>>()?;
    let destination = parse_operand(&req.destination)?;

    match destination {
        Operand::Remote(dest) => {
            if sources.iter().any(|s| matches!(s, Operand::Remote(_))) {
                return Err(OperandError::new(
                    "remote-to-remote copy is not supported; copy to this machine first \
                     (`qsh cp host:path .`) and then to the other host",
                ));
            }
            Ok(CopyPlan {
                direction: Direction::Put,
                host: dest.host.clone(),
                user: dest.user.clone(),
                sources: req.sources.clone(),
                destination: dest.wire_path(),
            })
        }
        Operand::Local(dest) => {
            let remotes: Vec<&RemoteOperand> = sources
                .iter()
                .filter_map(|s| match s {
                    Operand::Remote(r) => Some(r),
                    Operand::Local(_) => None,
                })
                .collect();
            if remotes.is_empty() {
                return Err(OperandError::new(
                    "no operand names a remote host (host:path); use cp for local copies",
                ));
            }
            if remotes.len() != sources.len() {
                return Err(OperandError::new(
                    "the sources mix local and remote paths; a copy is either to or from one host",
                ));
            }
            let first = remotes[0];
            if remotes
                .iter()
                .any(|r| r.host != first.host || r.user != first.user)
            {
                return Err(OperandError::new(
                    "the sources name more than one host or user; a copy involves one host",
                ));
            }
            Ok(CopyPlan {
                direction: Direction::Get,
                host: first.host.clone(),
                user: first.user.clone(),
                sources: remotes.iter().map(|r| r.wire_path()).collect(),
                destination: dest,
            })
        }
    }
}

/// The name an item is stored under when it is copied into a directory: the
/// last component of `path`. `None` when no name can be made (`.`, `..`,
/// `~`, an empty path, `/`), which is the "copy the contents" case of
/// decision 2.
pub fn source_name(path: &str) -> Option<&str> {
    let trimmed = path.trim_end_matches('/');
    let name = trimmed.rsplit('/').next().unwrap_or("");
    match name {
        "" | "." | ".." | "~" => None,
        name => Some(name),
    }
}

/// `base` with `name` appended as one more component. A plain string join:
/// the result is a display path derived from the operand, never a canonical
/// one.
pub fn join_path(base: &str, name: &str) -> String {
    let trimmed = base.trim_end_matches('/');
    if trimmed.is_empty() && base.starts_with('/') {
        format!("/{name}")
    } else if trimmed.is_empty() {
        name.to_string()
    } else {
        format!("{trimmed}/{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote(user: Option<&str>, host: &str, path: &str) -> Operand {
        Operand::Remote(RemoteOperand {
            user: user.map(str::to_string),
            host: host.to_string(),
            path: path.to_string(),
        })
    }

    fn req(sources: &[&str], destination: &str) -> FileCopyReq {
        FileCopyReq {
            sources: sources.iter().map(|s| s.to_string()).collect(),
            destination: destination.to_string(),
            recursive: false,
            preserve: false,
            no_clobber: false,
        }
    }

    #[test]
    fn cp_operand_grammar_separates_remote_from_local() {
        // A colon after the first slash belongs to a local file name.
        assert_eq!(
            parse_operand("./a:b").unwrap(),
            Operand::Local("./a:b".into())
        );
        assert_eq!(
            parse_operand("/tmp/a:b").unwrap(),
            Operand::Local("/tmp/a:b".into())
        );
        assert_eq!(
            parse_operand("plain").unwrap(),
            Operand::Local("plain".into())
        );
        // No host before the colon.
        assert_eq!(parse_operand(":x").unwrap(), Operand::Local(":x".into()));
        // The plain remote forms.
        assert_eq!(parse_operand("h:p").unwrap(), remote(None, "h", "p"));
        assert_eq!(
            parse_operand("host:dir/x").unwrap(),
            remote(None, "host", "dir/x")
        );
        assert_eq!(
            parse_operand("dave@host:/abs/x").unwrap(),
            remote(Some("dave"), "host", "/abs/x")
        );
        // `host:` is the home directory; the wire path says so.
        let Operand::Remote(home) = parse_operand("host:").unwrap() else {
            panic!("host: is remote");
        };
        assert_eq!(home.path, "");
        assert_eq!(home.wire_path(), "~");
        // A later colon or `@` in the path stays in the path.
        assert_eq!(
            parse_operand("host:a:b@c").unwrap(),
            remote(None, "host", "a:b@c")
        );
        // IPv6 literals are bracketed.
        assert_eq!(parse_operand("[::1]:p").unwrap(), remote(None, "::1", "p"));
        assert_eq!(
            parse_operand("dave@[fe80::1]:dir/x").unwrap(),
            remote(Some("dave"), "fe80::1", "dir/x")
        );
        assert_eq!(parse_operand("[::1]:").unwrap(), remote(None, "::1", ""));
        // A bracket without `]:` is a local name.
        assert_eq!(
            parse_operand("[abc]").unwrap(),
            Operand::Local("[abc]".into())
        );
        assert_eq!(
            parse_operand("[abc]x:y").unwrap(),
            Operand::Local("[abc]x:y".into())
        );
        // `-` and the empty operand are refused.
        assert!(parse_operand("-").is_err());
        assert!(parse_operand("").is_err());
        assert!(parse_operand("@host:x").is_err());
        assert!(parse_operand("[]:x").is_err());
    }

    #[test]
    fn cp_remote_to_remote_is_invalid_argument() {
        let err = plan(&req(&["a:x"], "b:y")).unwrap_err();
        assert!(err.message.contains("remote-to-remote"), "{err}");
        // Same host on both sides is still remote to remote.
        assert!(plan(&req(&["a:x"], "a:y")).is_err());
    }

    #[test]
    fn cp_mixed_operands_are_invalid_argument() {
        // Local and remote sources together.
        assert!(plan(&req(&["a:x", "local"], ".")).is_err());
        // Sources of two hosts, or two users on one host.
        assert!(plan(&req(&["a:x", "b:y"], ".")).is_err());
        assert!(plan(&req(&["u@a:x", "v@a:y"], ".")).is_err());
        // Nothing remote at all.
        assert!(plan(&req(&["x"], "y")).is_err());
        // `-` anywhere.
        assert!(plan(&req(&["-"], "a:y")).is_err());
        assert!(plan(&req(&["a:x"], "-")).is_err());
    }

    #[test]
    fn plan_reads_put_and_get() {
        let put = plan(&req(&["f", "./g"], "h:dir")).unwrap();
        assert_eq!(put.direction, Direction::Put);
        assert_eq!(put.host, "h");
        assert_eq!(put.sources, ["f", "./g"]);
        assert_eq!(put.destination, "dir");

        let put_home = plan(&req(&["f"], "u@h:")).unwrap();
        assert_eq!(put_home.destination, "~");
        assert_eq!(put_home.user.as_deref(), Some("u"));

        let get = plan(&req(&["h:a", "h:"], "out")).unwrap();
        assert_eq!(get.direction, Direction::Get);
        assert_eq!(get.sources, ["a", "~"]);
        assert_eq!(get.destination, "out");
    }

    #[test]
    fn source_names_and_joins() {
        assert_eq!(source_name("dir/x"), Some("x"));
        assert_eq!(source_name("x"), Some("x"));
        assert_eq!(source_name("~/x"), Some("x"));
        assert_eq!(source_name("dir/"), Some("dir"));
        for none in ["", "/", ".", "..", "~", "a/..", "a/.", "~/"] {
            assert_eq!(source_name(none), None, "{none:?}");
        }
        assert_eq!(join_path("~", "x"), "~/x");
        assert_eq!(join_path("dir/", "x"), "dir/x");
        assert_eq!(join_path("/", "x"), "/x");
        assert_eq!(join_path("/a/b", "x"), "/a/b/x");
    }
}
