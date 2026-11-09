//! The ssh options of the root `qsh [ssh options] [user@]host [command]`
//! form (ADR-0051 decisions 6 and 7).
//!
//! The rule is that **an ssh option describes the ssh path**: `-p 2222` is
//! sshd's port, never a UDP port. [`SshOptions`] therefore has two jobs. It
//! holds the argument list forwarded to the bootstrap's `ssh -G` and
//! responder calls (and, later, the revival call), and it holds the few
//! values that also mean something on the QUIC path: the address family, the
//! connect deadline, `BatchMode`, and the keep-alive and dead-peer knobs.
//!
//! [`SshOptions::from_flags`] is the only constructor. It validates every
//! value before any ssh process or socket exists, so a typo fails with
//! `INVALID_ARGUMENT` and the options the reject list names fail with
//! `UNSUPPORTED`, naming the option.

use std::time::Duration;

use qsh_proto::ErrorCode;

use super::jump_spec::{JumpHop, JumpSpec};

use crate::ops::OpError;

/// Address family filter of `-4` / `-6` / `-o AddressFamily` (applied to the
/// ssh call and to the QUIC dial alike).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AddressFamily {
    /// No filter.
    #[default]
    Any,
    /// `-4`: IPv4 only.
    V4,
    /// `-6`: IPv6 only.
    V6,
}

impl AddressFamily {
    /// Whether `addr` passes the filter.
    pub fn allows(self, addr: &std::net::SocketAddr) -> bool {
        match self {
            Self::Any => true,
            Self::V4 => addr.is_ipv4(),
            Self::V6 => addr.is_ipv6(),
        }
    }
}

/// The ssh options exactly as the person typed them. Nothing is validated
/// here; [`SshOptions::from_flags`] does that.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshFlags {
    /// `-p port`.
    pub port: Option<String>,
    /// `-i file`, repeatable.
    pub identity: Vec<String>,
    /// `-F file`.
    pub config_file: Option<String>,
    /// `-o Key=Val`, repeatable.
    pub options: Vec<String>,
    /// `-C`.
    pub compression: bool,
    /// `-4`.
    pub ipv4: bool,
    /// `-6`.
    pub ipv6: bool,
    /// `-J destination[,destination...]`.
    pub jump: Option<String>,
    /// The last of `-A` (`Some(true)`) and `-a` (`Some(false)`); `None`
    /// when neither was given.
    pub agent_forwarding: Option<bool>,
    /// Options ssh has and qsh refuses (`-X`, `-W`, ...), as typed with
    /// their dash.
    pub rejected: Vec<String>,
}

/// Validated ssh options.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshOptions {
    forwarded: Vec<String>,
    family: AddressFamily,
    jump: Option<String>,
    jump_spec: Option<JumpSpec>,
    connect_timeout: Option<Duration>,
    batch_mode: bool,
    server_alive_interval: Option<Duration>,
    server_alive_count_max: Option<u32>,
    agent_flag: Option<bool>,
    forward_agent: Option<String>,
}

impl SshOptions {
    /// Validate `flags`.
    ///
    /// - A rejected option is `UNSUPPORTED` and names the option
    ///   (`-W` is rejected by ADR-0011).
    /// - `-p` must be a port, `-4` and `-6` do not combine, and `-o` values
    ///   that qsh also reads (`ConnectTimeout`, `BatchMode`,
    ///   `ServerAliveInterval`, `ServerAliveCountMax`, `AddressFamily`,
    ///   `ForwardAgent`) must parse. Every other `-o` key is ssh's to judge and is forwarded.
    pub fn from_flags(flags: &SshFlags) -> Result<Self, OpError> {
        if let Some(first) = flags.rejected.first() {
            let why = if first == "-W" {
                "stdio forwarding was rejected by ADR-0011"
            } else {
                "qsh has no equivalent of this ssh option"
            };
            return Err(unsupported(format!(
                "ssh option {first} is not supported ({why})"
            )));
        }
        if flags.ipv4 && flags.ipv6 {
            return Err(invalid("-4 and -6 do not combine"));
        }
        let mut out = Self {
            agent_flag: flags.agent_forwarding,
            ..Self::default()
        };
        if let Some(file) = &flags.config_file {
            out.forwarded.push("-F".into());
            out.forwarded.push(checked_word("-F", file)?);
        }
        if let Some(port) = &flags.port {
            match port.parse::<u16>() {
                Ok(p) if p != 0 => {}
                _ => {
                    return Err(invalid(format!(
                        "-p expects a port (1-65535), got {port:?}"
                    )));
                }
            }
            out.forwarded.push("-p".into());
            out.forwarded.push(port.clone());
        }
        for file in &flags.identity {
            out.forwarded.push("-i".into());
            out.forwarded.push(checked_word("-i", file)?);
        }
        if let Some(jump) = &flags.jump {
            out.forwarded.push("-J".into());
            out.forwarded.push(checked_word("-J", jump)?);
            out.jump_spec = Some(JumpSpec::parse(jump)?);
            out.jump = (out.jump_spec != Some(JumpSpec::Off)).then(|| jump.clone());
        }
        if flags.compression {
            out.forwarded.push("-C".into());
        }
        if flags.ipv4 {
            out.forwarded.push("-4".into());
            out.family = AddressFamily::V4;
        }
        if flags.ipv6 {
            out.forwarded.push("-6".into());
            out.family = AddressFamily::V6;
        }
        let mut seen: Vec<String> = Vec::new();
        for text in &flags.options {
            let (key, value) = split_option(text)?;
            out.forwarded.push("-o".into());
            out.forwarded.push(text.clone());
            let lower = key.to_ascii_lowercase();
            // ssh keeps the first value of a repeated key.
            if seen.contains(&lower) {
                continue;
            }
            seen.push(lower.clone());
            match lower.as_str() {
                "connecttimeout" => {
                    out.connect_timeout = if value.eq_ignore_ascii_case("none") {
                        None
                    } else {
                        Some(parse_ssh_time(&key, &value)?)
                    };
                }
                "batchmode" => out.batch_mode = parse_yes_no(&key, &value)?,
                "forwardagent" => {
                    // Only the shape is checked here; `Ops::with_agent_forward`
                    // decides what it means (ADR-0055 decision 18). The
                    // option still goes to the bootstrap ssh like any other
                    // `-o`, behind the fixed `-a`.
                    crate::agent::ForwardAgentOption::parse(&value)?;
                    out.forward_agent = Some(value.clone());
                }
                "serveraliveinterval" => {
                    let interval = parse_ssh_time(&key, &value)?;
                    out.server_alive_interval = (!interval.is_zero()).then_some(interval);
                }
                "serveralivecountmax" => match value.parse::<u32>() {
                    Ok(n) if n >= 1 => out.server_alive_count_max = Some(n),
                    _ => {
                        return Err(invalid(format!(
                            "{key} expects a positive number, got {value:?}"
                        )));
                    }
                },
                "addressfamily" => {
                    let family = match value.to_ascii_lowercase().as_str() {
                        "any" => AddressFamily::Any,
                        "inet" => AddressFamily::V4,
                        "inet6" => AddressFamily::V6,
                        _ => {
                            return Err(invalid(format!(
                                "{key} expects any, inet or inet6, got {value:?}"
                            )));
                        }
                    };
                    // -4 / -6 win over the option, like ssh.
                    if out.family == AddressFamily::Any {
                        out.family = family;
                    }
                }
                "proxyjump" if out.jump_spec.is_none() => {
                    out.jump_spec = Some(JumpSpec::parse(&value)?);
                    out.jump = (out.jump_spec != Some(JumpSpec::Off)).then(|| value.clone());
                }
                _ => {}
            }
        }
        Ok(out)
    }

    /// The arguments forwarded to ssh, in a fixed order: `-F`, `-p`, `-i`,
    /// `-J`, `-C`, `-4`/`-6`, then every `-o` as typed.
    pub fn forwarded_args(&self) -> &[String] {
        &self.forwarded
    }

    /// The address family filter.
    pub fn family(&self) -> AddressFamily {
        self.family
    }

    /// The jump host list from `-J` or `-o ProxyJump`, when one was given.
    /// It applies to the ssh path only; a QUIC-path jump is `UNSUPPORTED`
    /// until M26.
    pub fn jump(&self) -> Option<&str> {
        self.jump.as_deref()
    }

    /// The last of `-A` (`Some(true)`) and `-a` (`Some(false)`).
    pub fn agent_flag(&self) -> Option<bool> {
        self.agent_flag
    }

    /// The value of the first `-o ForwardAgent=`: `yes`, `no`, a path or
    /// `$VAR` (ADR-0055 decision 18).
    pub fn forward_agent(&self) -> Option<&str> {
        self.forward_agent.as_deref()
    }

    /// `-o ConnectTimeout`, as the QUIC dial deadline.
    pub fn connect_timeout(&self) -> Option<Duration> {
        self.connect_timeout
    }

    /// `-o BatchMode=yes`: no question may be asked.
    pub fn batch_mode(&self) -> bool {
        self.batch_mode
    }

    /// `-o ServerAliveInterval`, as the keep-alive interval.
    pub fn server_alive_interval(&self) -> Option<Duration> {
        self.server_alive_interval
    }

    /// `-o ServerAliveCountMax`, as the number of unanswered path probes
    /// that declare the path dead.
    pub fn server_alive_count_max(&self) -> Option<u32> {
        self.server_alive_count_max
    }

    /// What `-J` or the first `-o ProxyJump=` says about the QUIC path
    /// (ADR-0056 decision 20): `Hops` to go through them, `Off` for `none`,
    /// `None` when neither was given and the pin's own `jump` decides.
    /// `-J` wins over the option, like ssh.
    pub fn jump_spec(&self) -> Option<&JumpSpec> {
        self.jump_spec.as_ref()
    }

    /// These options for the bootstrap of one jump hop (ADR-0056 decision
    /// 21): what describes the end target's own ssh path (`-p`, `-J`, `-o
    /// ProxyJump`) is replaced by the hop's: `before` are the hops in front
    /// of it, passed as ssh's `-J`, and `port` is its sshd port. Everything
    /// else (`-F`, `-i`, `-o`, `-4`, ...) carries over.
    #[must_use]
    pub fn for_jump_hop(&self, before: &[JumpHop], port: Option<u16>) -> SshOptions {
        let mut out = self.clone();
        let mut kept = Vec::with_capacity(self.forwarded.len());
        let mut words = self.forwarded.iter();
        while let Some(word) = words.next() {
            match word.as_str() {
                "-p" | "-J" => {
                    words.next();
                }
                "-o" => {
                    let Some(text) = words.next() else { break };
                    let key = text
                        .split(['=', ' ', '\t'])
                        .next()
                        .unwrap_or_default()
                        .to_ascii_lowercase();
                    if key != "proxyjump" {
                        kept.push(word.clone());
                        kept.push(text.clone());
                    }
                }
                "-F" | "-i" => {
                    kept.push(word.clone());
                    if let Some(value) = words.next() {
                        kept.push(value.clone());
                    }
                }
                _ => kept.push(word.clone()),
            }
        }
        if let Some(port) = port {
            kept.push("-p".into());
            kept.push(port.to_string());
        }
        out.jump = None;
        out.jump_spec = None;
        if !before.is_empty() {
            let list = before
                .iter()
                .map(|hop| hop.dest.as_str())
                .collect::<Vec<_>>()
                .join(",");
            kept.push("-J".into());
            kept.push(list.clone());
            out.jump = Some(list);
            out.jump_spec = Some(JumpSpec::Hops(before.to_vec()));
        }
        out.forwarded = kept;
        out
    }

    /// Whether anything was given at all.
    pub fn is_empty(&self) -> bool {
        self.forwarded.is_empty()
    }
}

fn invalid(message: impl Into<String>) -> OpError {
    OpError::new(ErrorCode::InvalidArgument, message).with_retryable(false)
}

fn unsupported(message: impl Into<String>) -> OpError {
    OpError::new(ErrorCode::Unsupported, message).with_retryable(false)
}

/// A value that becomes one ssh argument: non-empty, no control characters.
fn checked_word(option: &str, value: &str) -> Result<String, OpError> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(invalid(format!(
            "{option} expects a non-empty value without control characters"
        )));
    }
    Ok(value.to_string())
}

/// Split `Key=Val` or `Key Val` like ssh's `-o`.
fn split_option(text: &str) -> Result<(String, String), OpError> {
    if text.chars().any(char::is_control) {
        return Err(invalid("-o must not contain control characters"));
    }
    let text = text.trim();
    let at = text.find(|c: char| c == '=' || c.is_whitespace());
    let (key, rest) = match at {
        Some(at) => (&text[..at], &text[at..]),
        None => (text, ""),
    };
    let value = rest
        .trim_start_matches(|c: char| c.is_whitespace())
        .trim_start_matches('=')
        .trim();
    if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric()) || value.is_empty() {
        return Err(invalid(format!("-o expects Key=Value, got {text:?}")));
    }
    Ok((key.to_string(), value.to_string()))
}

fn parse_yes_no(key: &str, value: &str) -> Result<bool, OpError> {
    match value.to_ascii_lowercase().as_str() {
        "yes" | "true" => Ok(true),
        "no" | "false" => Ok(false),
        _ => Err(invalid(format!("{key} expects yes or no, got {value:?}"))),
    }
}

/// ssh's time format: seconds, or a sum of `<n>[smhdw]` terms (`90`, `1m30s`).
fn parse_ssh_time(key: &str, value: &str) -> Result<Duration, OpError> {
    let bad = || {
        invalid(format!(
            "{key} expects a time like 10 or 1m30s, got {value:?}"
        ))
    };
    let mut total: u64 = 0;
    let mut digits = String::new();
    for c in value.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        let unit: u64 = match c.to_ascii_lowercase() {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86_400,
            'w' => 604_800,
            _ => return Err(bad()),
        };
        let n: u64 = digits.parse().map_err(|_| bad())?;
        digits.clear();
        total = total
            .checked_add(n.checked_mul(unit).ok_or_else(bad)?)
            .ok_or_else(bad)?;
    }
    if !digits.is_empty() {
        let n: u64 = digits.parse().map_err(|_| bad())?;
        total = total.checked_add(n).ok_or_else(bad)?;
    }
    if total == 0 && value.is_empty() {
        return Err(bad());
    }
    Ok(Duration::from_secs(total))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags() -> SshFlags {
        SshFlags::default()
    }

    #[test]
    fn forwarded_order_is_fixed() {
        let f = SshFlags {
            port: Some("2222".into()),
            identity: vec!["k1".into(), "k2".into()],
            config_file: Some("cfg".into()),
            options: vec!["StrictHostKeyChecking=no".into()],
            compression: true,
            ipv6: true,
            jump: Some("bastion".into()),
            ..flags()
        };
        let o = SshOptions::from_flags(&f).unwrap();
        assert_eq!(
            o.forwarded_args(),
            [
                "-F",
                "cfg",
                "-p",
                "2222",
                "-i",
                "k1",
                "-i",
                "k2",
                "-J",
                "bastion",
                "-C",
                "-6",
                "-o",
                "StrictHostKeyChecking=no"
            ]
        );
        assert_eq!(o.family(), AddressFamily::V6);
        assert_eq!(o.jump(), Some("bastion"));
    }

    #[test]
    fn quic_side_values_come_from_the_first_occurrence() {
        let f = SshFlags {
            options: vec![
                "ConnectTimeout=5".into(),
                "ConnectTimeout=50".into(),
                "BatchMode yes".into(),
                "ServerAliveInterval=1m".into(),
                "ServerAliveCountMax=4".into(),
                "ProxyJump=hop".into(),
            ],
            ..flags()
        };
        let o = SshOptions::from_flags(&f).unwrap();
        assert_eq!(o.connect_timeout(), Some(Duration::from_secs(5)));
        assert!(o.batch_mode());
        assert_eq!(o.server_alive_interval(), Some(Duration::from_secs(60)));
        assert_eq!(o.server_alive_count_max(), Some(4));
        assert_eq!(o.jump(), Some("hop"));
    }

    #[test]
    fn bad_values_are_invalid_argument() {
        for opts in [
            vec!["ConnectTimeout=soon"],
            vec!["BatchMode=maybe"],
            vec!["ServerAliveCountMax=0"],
            vec!["novalue"],
            vec!["AddressFamily=both"],
        ] {
            let f = SshFlags {
                options: opts.iter().map(|s| (*s).to_string()).collect(),
                ..flags()
            };
            let err = SshOptions::from_flags(&f).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "{opts:?}");
        }
        let f = SshFlags {
            port: Some("70000".into()),
            ..flags()
        };
        assert_eq!(
            SshOptions::from_flags(&f).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
        let f = SshFlags {
            ipv4: true,
            ipv6: true,
            ..flags()
        };
        assert_eq!(
            SshOptions::from_flags(&f).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn rejected_options_are_unsupported_and_named() {
        let f = SshFlags {
            rejected: vec!["-W".into()],
            ..flags()
        };
        let err = SshOptions::from_flags(&f).unwrap_err();
        assert_eq!(err.code, ErrorCode::Unsupported);
        assert!(err.message.contains("-W"), "{}", err.message);
    }

    #[test]
    fn agent_flags_and_forward_agent_are_read_not_forwarded() {
        let f = SshFlags {
            agent_forwarding: Some(true),
            options: vec![
                "ForwardAgent=/s/agent.sock".into(),
                "ForwardAgent=no".into(),
            ],
            ..flags()
        };
        let o = SshOptions::from_flags(&f).unwrap();
        assert_eq!(o.agent_flag(), Some(true));
        // The first value wins, as in ssh.
        assert_eq!(o.forward_agent(), Some("/s/agent.sock"));
        // `-A` is never passed to the bootstrap ssh; only the `-o`s are.
        assert!(!o.forwarded_args().iter().any(|a| a == "-A"));
        let bad = SshFlags {
            options: vec!["ForwardAgent=".into()],
            ..flags()
        };
        assert!(SshOptions::from_flags(&bad).is_err());
    }

    #[test]
    fn ssh_time_forms() {
        assert_eq!(parse_ssh_time("k", "90").unwrap(), Duration::from_secs(90));
        assert_eq!(
            parse_ssh_time("k", "1m30s").unwrap(),
            Duration::from_secs(90)
        );
        assert!(parse_ssh_time("k", "1x").is_err());
    }
}
