//! The prompt registry (ADR-0051 decision 13): every interactive question qsh
//! asks is a row here, together with the flag that gives the same answer and
//! what a run without a terminal does instead.
//!
//! A question is only ever asked when stdin is a terminal and the run is not
//! in machine mode (`--json`/`--jsonl`). Everywhere else [`ask`] returns
//! `Ok(None)` without writing a byte, and the caller falls back to the row's
//! non-interactive behavior. `prompts::tests` pins both rules: every row
//! names at least one flag, and no row is shown without a terminal.
//!
//! Other questions belong here too (the remote install, the pin replacement):
//! add a row to [`REGISTRY`], and a flag to the command line that gives the
//! same answer.

use std::io::{self, BufRead, IsTerminal as _, Write};

/// One interactive question.
#[derive(Debug, PartialEq, Eq)]
pub struct Prompt {
    /// Stable identifier, for tests and docs.
    pub id: &'static str,
    /// The question, without the `[Y/n]` suffix.
    pub question: &'static str,
    /// Whether an empty answer means yes.
    pub default_yes: bool,
    /// The long flags that give the same answer without a prompt. At least one.
    pub flags: &'static [&'static str],
    /// What a run that cannot ask does (docs/CLI.md, one line).
    pub non_interactive: &'static str,
}

/// Before `service install --always-on` on a `platform` key store that does
/// not open outside a login session (macOS, Linux).
pub const MOVE_KEY: Prompt = Prompt {
    id: "service.always_on.move_key",
    question: "키를 파일 저장소로 옮길까?",
    default_yes: true,
    flags: &["--move-key"],
    non_interactive: "fails with details.reason keystore_session_bound",
};

/// During `pair ssh` (and the automatic bootstrap), when a pin holds another
/// fingerprint than the one the ssh login now reaches (ADR-0051 decision 5).
/// The old and new fingerprints are shown first ([`Prompter::note`]).
pub const REPLACE_PIN: Prompt = Prompt {
    id: "pair.ssh.replace_pin",
    question: "pin을 바꿀까?",
    default_yes: false,
    flags: &["--replace-pin"],
    non_interactive: "fails with SESSION_CONFLICT and details.reason pin_conflict",
};

/// Every registered question.
pub const REGISTRY: &[&Prompt] = &[&MOVE_KEY, &REPLACE_PIN];

/// Where a question may be asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PromptEnv {
    /// Whether stdin is a terminal.
    pub stdin_is_terminal: bool,
    /// `--json` or `--jsonl`.
    pub machine_mode: bool,
}

impl PromptEnv {
    /// The environment of this process.
    pub fn detect(machine_mode: bool) -> Self {
        Self {
            stdin_is_terminal: io::stdin().is_terminal(),
            machine_mode,
        }
    }

    /// Whether a question may be shown.
    pub fn can_ask(&self) -> bool {
        self.stdin_is_terminal && !self.machine_mode
    }
}

/// Asks `prompt` on `writer`, reads one line from `reader`. `Ok(None)` when
/// `env` does not allow a question (nothing is written) or when the input
/// ended without an answer. An empty line is the prompt's default, `y`/`yes`
/// and `n`/`no` (any case) answer, and anything else asks once more before
/// giving up as `None`.
pub fn ask(
    prompt: &Prompt,
    env: &PromptEnv,
    reader: &mut dyn BufRead,
    writer: &mut dyn Write,
) -> io::Result<Option<bool>> {
    if !env.can_ask() {
        return Ok(None);
    }
    let suffix = if prompt.default_yes { "[Y/n]" } else { "[y/N]" };
    for _ in 0..2 {
        write!(writer, "{} {suffix} ", prompt.question)?;
        writer.flush()?;
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(None);
        }
        match line.trim().to_ascii_lowercase().as_str() {
            "" => return Ok(Some(prompt.default_yes)),
            "y" | "yes" => return Ok(Some(true)),
            "n" | "no" => return Ok(Some(false)),
            _ => {}
        }
    }
    Ok(None)
}

/// The seam an op asks its questions through. `None` means "not asked".
pub trait Prompter: Send + Sync {
    /// Ask `prompt`, or return `None` when it cannot be asked here.
    fn ask(&self, prompt: &Prompt) -> Option<bool>;

    /// Show context a question needs (for example the two fingerprints
    /// [`REPLACE_PIN`] compares) right before it is asked. Written only where
    /// a question could be asked; the default shows nothing.
    fn note(&self, _text: &str) {}
}

/// The prompter of every run that asks nothing.
pub struct NoPrompter;

impl Prompter for NoPrompter {
    fn ask(&self, _prompt: &Prompt) -> Option<bool> {
        None
    }
}

/// Asks on stderr and reads stdin, when [`PromptEnv::can_ask`].
pub struct StdioPrompter {
    env: PromptEnv,
}

impl StdioPrompter {
    /// A prompter for this process; `machine_mode` is `--json`/`--jsonl`.
    pub fn new(machine_mode: bool) -> Self {
        Self {
            env: PromptEnv::detect(machine_mode),
        }
    }
}

impl Prompter for StdioPrompter {
    fn note(&self, text: &str) {
        if self.env.can_ask() {
            let _ = writeln!(io::stderr().lock(), "{text}");
        }
    }

    fn ask(&self, prompt: &Prompt) -> Option<bool> {
        let stdin = io::stdin();
        let mut reader = stdin.lock();
        let mut stderr = io::stderr().lock();
        ask(prompt, &self.env, &mut reader, &mut stderr)
            .ok()
            .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_registered_prompt_has_a_long_flag_and_a_unique_id() {
        assert!(!REGISTRY.is_empty());
        let mut ids = std::collections::BTreeSet::new();
        for prompt in REGISTRY {
            assert!(
                !prompt.flags.is_empty() && prompt.flags.iter().all(|f| f.starts_with("--")),
                "{} has no `--flag` with the same answer",
                prompt.id
            );
            assert!(!prompt.non_interactive.is_empty(), "{}", prompt.id);
            assert!(ids.insert(prompt.id), "duplicate id {}", prompt.id);
        }
    }

    #[test]
    fn no_prompt_is_shown_without_a_terminal_or_in_machine_mode() {
        for (stdin_is_terminal, machine_mode) in [(false, false), (true, true), (false, true)] {
            let env = PromptEnv {
                stdin_is_terminal,
                machine_mode,
            };
            for prompt in REGISTRY {
                let mut out = Vec::new();
                let mut input = io::Cursor::new(b"y\n".to_vec());
                let answer = ask(prompt, &env, &mut input, &mut out).unwrap();
                assert_eq!(answer, None, "{}", prompt.id);
                assert!(out.is_empty(), "{} wrote {out:?}", prompt.id);
                assert_eq!(input.position(), 0, "{} read input", prompt.id);
            }
        }
    }

    #[test]
    fn a_prompt_on_a_terminal_reads_the_answer_and_honors_the_default() {
        let env = PromptEnv {
            stdin_is_terminal: true,
            machine_mode: false,
        };
        for (input, expected) in [
            ("\n", Some(true)),
            ("y\n", Some(true)),
            ("YES\n", Some(true)),
            ("n\n", Some(false)),
            ("", None),
            ("maybe\nmaybe\n", None),
            ("maybe\nn\n", Some(false)),
        ] {
            let mut out = Vec::new();
            let mut reader = io::Cursor::new(input.as_bytes().to_vec());
            let answer = ask(&MOVE_KEY, &env, &mut reader, &mut out).unwrap();
            assert_eq!(answer, expected, "{input:?}");
            assert!(String::from_utf8(out).unwrap().contains("[Y/n]"));
        }
    }

    #[test]
    fn the_replace_pin_row_defaults_to_no_and_names_its_flag() {
        assert!(REGISTRY.contains(&&REPLACE_PIN));
        assert!(!std::hint::black_box(REPLACE_PIN.default_yes));
        assert_eq!(REPLACE_PIN.flags, &["--replace-pin"]);
        assert!(REPLACE_PIN.non_interactive.contains("pin_conflict"));
        let env = PromptEnv {
            stdin_is_terminal: true,
            machine_mode: false,
        };
        let mut out = Vec::new();
        let mut reader = io::Cursor::new(b"\n".to_vec());
        assert_eq!(
            ask(&REPLACE_PIN, &env, &mut reader, &mut out).unwrap(),
            Some(false)
        );
        assert!(String::from_utf8(out).unwrap().contains("[y/N]"));
    }
}
