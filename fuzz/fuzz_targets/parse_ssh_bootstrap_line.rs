//! Fuzzes `qsh_proto::ssh_bootstrap` — the line parser
//! `parse_ssh_bootstrap_line` and the incremental `BootstrapReader` that
//! `qsh pair ssh` points at the stdout of its `ssh` child (ADR-0044
//! decision 11). That stdout is whatever the remote account prints: the
//! shell's rc output before the responder's `hello`, then the responder's
//! messages, so it is untrusted input even though ssh authenticated the
//! account. The stream is not a QUIC wire message, but it is an
//! interoperability contract between two qsh builds
//! (`docs/design/protocol.md` §17), so it sits on the same fuzz surface as
//! the other `qsh-proto` parsers (§13).
//!
//! The first input byte picks how the rest is chunked when fed to the
//! reader (`0` = the whole buffer in one call, `n` = pieces of `n` bytes),
//! so one corpus entry covers both the one-shot and the trickling pipe.
//!
//! Invariants checked on every input:
//!
//! - no panic, on any bytes (libFuzzer treats a panic as a crash);
//! - a line the parser accepts re-encodes to a line that parses back to an
//!   equal value (unless the re-encoding is refused as over-long), and the
//!   encoding is a single `\n`-terminated line;
//! - the reader's outcome (messages, skipped line and byte counts, or the
//!   error) does not depend on how the bytes were chunked;
//! - skipped bytes never exceed `BOOTSTRAP_PREAMBLE_MAX` on success.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_proto::ssh_bootstrap::{
    BOOTSTRAP_LINE_MAX, BOOTSTRAP_PREAMBLE_MAX, BootstrapLine, BootstrapLineError, BootstrapReader,
    parse_ssh_bootstrap_line,
};

type Outcome = Result<(Vec<BootstrapLine>, u32, usize), BootstrapLineError>;

fn run(data: &[u8], chunk: usize) -> Outcome {
    let mut reader = BootstrapReader::new();
    let mut out = Vec::new();
    if chunk == 0 {
        out.extend(reader.push(data)?);
    } else {
        for piece in data.chunks(chunk) {
            out.extend(reader.push(piece)?);
        }
    }
    assert!(reader.skipped_bytes() <= BOOTSTRAP_PREAMBLE_MAX);
    Ok((out, reader.skipped_lines(), reader.skipped_bytes()))
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };

    // The line parser, on the rest as one line and on each of its lines.
    for line in std::iter::once(rest).chain(rest.split(|&b| b == b'\n')) {
        if let Ok(msg) = parse_ssh_bootstrap_line(line) {
            match msg.encode_line() {
                Ok(encoded) => {
                    assert!(encoded.ends_with('\n'));
                    assert_eq!(encoded.matches('\n').count(), 1);
                    let again = parse_ssh_bootstrap_line(encoded.trim_end_matches('\n').as_bytes());
                    assert_eq!(again, Ok(msg));
                }
                Err(BootstrapLineError::LineTooLong) => {
                    // An accepted line can re-encode longer than the cap only
                    // by escaping; nothing to compare then.
                }
                Err(e) => panic!("accepted message failed to encode: {e}"),
            }
        }
        if line.len() > BOOTSTRAP_LINE_MAX + 1 {
            assert!(parse_ssh_bootstrap_line(line).is_err());
        }
    }

    // The reader: same result however the pipe splits the bytes.
    let whole = run(rest, 0);
    let chunked = run(rest, selector as usize);
    assert_eq!(whole, chunked);
    assert_eq!(whole, run(rest, 1));
});
