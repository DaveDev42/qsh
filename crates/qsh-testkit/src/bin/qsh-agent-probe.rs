//! The program on the host in the agent-forwarding tests (ADR-0055 decision
//! 23): a tiny ssh-agent client that works the same on every OS, so the tests
//! need neither `python3` nor a Unix socket. It talks to `$SSH_AUTH_SOCK`,
//! which is a Unix socket path on unix and a named pipe name on Windows.
//!
//! ```text
//! qsh-agent-probe call [--tag LABEL] KIND[:BODY_HEX]...
//! qsh-agent-probe sock
//! ```
//!
//! - `call` opens one connection and sends each message in turn (`KIND` is
//!   the agent message type in decimal, `BODY_HEX` the body after the type
//!   byte), reading one whole reply after each. It prints every reply, without
//!   its length prefix, as one lowercase hex line. With `--tag LABEL` the line
//!   is `AGENT<LABEL>:<hex>`; the tag is assembled here so the typed command
//!   line of a shell test never contains the text it waits for. Exit code 3
//!   means the connection closed before a reply, 2 a bad argument or no
//!   `SSH_AUTH_SOCK`.
//! - `sock` prints `$SSH_AUTH_SOCK`, or `unset`, with no newline.
//!
//! Nothing here validates the replies; the tests compare them byte for byte.

use std::io::{Read, Write};
use std::process::ExitCode;

#[cfg(unix)]
type Conn = std::os::unix::net::UnixStream;
#[cfg(windows)]
type Conn = std::fs::File;

#[cfg(unix)]
fn connect(endpoint: &str) -> std::io::Result<Conn> {
    Conn::connect(endpoint)
}

/// A named pipe opens like a file. `ERROR_PIPE_BUSY` (231) means every
/// instance is momentarily taken, so retry briefly.
#[cfg(windows)]
fn connect(endpoint: &str) -> std::io::Result<Conn> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(endpoint)
        {
            Err(err) if err.raw_os_error() == Some(231) && std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            other => return other,
        }
    }
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// One message: `KIND[:BODY_HEX]` as `length(4) type(1) body`.
fn message(arg: &str) -> Option<Vec<u8>> {
    let (kind, body) = arg.split_once(':').unwrap_or((arg, ""));
    let kind: u8 = kind.parse().ok()?;
    let body = unhex(body)?;
    let len = u32::try_from(body.len() + 1).ok()?;
    let mut out = len.to_be_bytes().to_vec();
    out.push(kind);
    out.extend_from_slice(&body);
    Some(out)
}

fn call(tag: Option<&str>, args: &[String]) -> ExitCode {
    let Some(endpoint) = std::env::var_os("SSH_AUTH_SOCK") else {
        eprintln!("SSH_AUTH_SOCK is not set");
        return ExitCode::from(2);
    };
    let Some(endpoint) = endpoint.to_str() else {
        return ExitCode::from(2);
    };
    let Some(messages) = args.iter().map(|a| message(a)).collect::<Option<Vec<_>>>() else {
        eprintln!("a message must be KIND or KIND:BODY_HEX");
        return ExitCode::from(2);
    };
    let mut conn = match connect(endpoint) {
        Ok(conn) => conn,
        Err(err) => {
            eprintln!("connect failed: {:?}", err.kind());
            return ExitCode::from(3);
        }
    };
    for msg in messages {
        let mut len = [0u8; 4];
        let reply = conn
            .write_all(&msg)
            .and_then(|()| conn.read_exact(&mut len))
            .and_then(|()| {
                let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
                conn.read_exact(&mut body).map(|()| body)
            });
        let Ok(body) = reply else {
            return ExitCode::from(3);
        };
        let line = match tag {
            Some(tag) => format!("AGENT{tag}:{}", hex(&body)),
            None => hex(&body),
        };
        let mut out = std::io::stdout().lock();
        if writeln!(out, "{line}").and_then(|()| out.flush()).is_err() {
            return ExitCode::from(3);
        }
    }
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("sock") => {
            let value = std::env::var("SSH_AUTH_SOCK").unwrap_or_else(|_| "unset".into());
            print!("{value}");
            let _ = std::io::stdout().flush();
            ExitCode::SUCCESS
        }
        Some("call") => match args.get(1).map(String::as_str) {
            Some("--tag") => match args.get(2) {
                Some(tag) => call(Some(tag), &args[3..]),
                None => ExitCode::from(2),
            },
            _ => call(None, &args[1..]),
        },
        _ => {
            eprintln!("usage: qsh-agent-probe call [--tag LABEL] KIND[:BODY_HEX]... | sock");
            ExitCode::from(2)
        }
    }
}
