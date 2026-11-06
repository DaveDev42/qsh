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
//! Other questions belong here too (the pin replacement): add a row to
//! [`REGISTRY`], and a flag to the command line that gives the same answer.

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

/// The remote host has no `qsh` (ADR-0051 decision 3). The text shown names
/// the host and the version ([`ask_text`]); `question` is the fixed part.
pub const INSTALL_REMOTE: Prompt = Prompt {
    id: "ssh.install_remote",
    question: "Install qsh on the remote host?",
    default_yes: true,
    flags: &["--install-remote", "--no-install-remote"],
    non_interactive: "does not install; ends with details.reason remote_qsh_missing",
};

/// The remote host's `qsh` is too old for the bootstrap (ADR-0051 decision
/// 3). A running serve is not touched.
pub const UPGRADE_REMOTE: Prompt = Prompt {
    id: "ssh.upgrade_remote",
    question: "Upgrade qsh on the remote host?",
    default_yes: true,
    flags: &["--install-remote"],
    non_interactive: "does not upgrade; ends with details.reason remote_qsh_too_old",
};

/// Every registered question.
pub const REGISTRY: &[&Prompt] = &[&MOVE_KEY, &REPLACE_PIN, &INSTALL_REMOTE, &UPGRADE_REMOTE];

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
    ask_text(prompt, prompt.question, env, reader, writer)
}

/// [`ask`] with `question` shown instead of `prompt.question`, for a
/// question that names a host or a version. The registry row still decides
/// the default and the flags, and whether it may be asked at all.
pub fn ask_text(
    prompt: &Prompt,
    question: &str,
    env: &PromptEnv,
    reader: &mut dyn BufRead,
    writer: &mut dyn Write,
) -> io::Result<Option<bool>> {
    if !env.can_ask() {
        return Ok(None);
    }
    let suffix = if prompt.default_yes { "[Y/n]" } else { "[y/N]" };
    for _ in 0..2 {
        write!(writer, "{question} {suffix} ")?;
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

    /// Ask `prompt` with `question` as the text shown ([`ask_text`]), for a
    /// question that names a host or a version. A prompter that cannot show
    /// custom text answers as [`Self::ask`] does.
    fn ask_text(&self, prompt: &Prompt, question: &str) -> Option<bool> {
        let _ = question;
        self.ask(prompt)
    }
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
        self.ask_text(prompt, prompt.question)
    }

    fn ask_text(&self, prompt: &Prompt, question: &str) -> Option<bool> {
        let stdin = io::stdin();
        let mut reader = stdin.lock();
        let mut stderr = io::stderr().lock();
        ask_text(prompt, question, &self.env, &mut reader, &mut stderr)
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

    /// ADR-0051 decision 13's table is the whole registry: the four questions
    /// M21 adds, each with the flag that answers it. Adding a question means
    /// changing this list and the ADR together.
    #[test]
    fn the_registry_is_exactly_the_four_questions_of_decision_13() {
        let rows: Vec<(&str, &[&str])> = REGISTRY.iter().map(|p| (p.id, p.flags)).collect();
        assert_eq!(
            rows,
            [
                ("service.always_on.move_key", &["--move-key"][..]),
                ("pair.ssh.replace_pin", &["--replace-pin"][..]),
                (
                    "ssh.install_remote",
                    &["--install-remote", "--no-install-remote"][..]
                ),
                ("ssh.upgrade_remote", &["--install-remote"][..]),
            ]
        );
        // Their non-interactive fallbacks are the reasons the table names.
        let fallback = |id: &str| {
            REGISTRY
                .iter()
                .find(|p| p.id == id)
                .unwrap()
                .non_interactive
        };
        assert!(fallback("service.always_on.move_key").contains("keystore_session_bound"));
        assert!(fallback("pair.ssh.replace_pin").contains("pin_conflict"));
        assert!(fallback("ssh.install_remote").contains("remote_qsh_missing"));
        assert!(fallback("ssh.upgrade_remote").contains("remote_qsh_too_old"));
    }

    /// ADR-0051 decision 13: the remote install and upgrade rows and their
    /// flags.
    #[test]
    fn the_remote_install_rows_are_registered_with_their_flags() {
        let row = |id: &str| REGISTRY.iter().find(|p| p.id == id).copied().unwrap();
        assert_eq!(
            row("ssh.install_remote").flags,
            ["--install-remote", "--no-install-remote"]
        );
        assert_eq!(row("ssh.upgrade_remote").flags, ["--install-remote"]);
        for id in ["ssh.install_remote", "ssh.upgrade_remote"] {
            assert!(row(id).default_yes, "{id}");
            assert!(row(id).non_interactive.contains("remote_qsh_"), "{id}");
        }
    }

    /// A question with its own text still follows the registry's rule.
    #[test]
    fn a_custom_question_text_is_shown_only_where_the_row_may_be_asked() {
        let terminal = PromptEnv {
            stdin_is_terminal: true,
            machine_mode: false,
        };
        let mut out = Vec::new();
        let mut input = io::Cursor::new(b"n\n".to_vec());
        let answer = ask_text(
            &INSTALL_REMOTE,
            "box has no qsh. Install?",
            &terminal,
            &mut input,
            &mut out,
        )
        .unwrap();
        assert_eq!(answer, Some(false));
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "box has no qsh. Install? [Y/n] "
        );

        let machine = PromptEnv {
            stdin_is_terminal: true,
            machine_mode: true,
        };
        let mut out = Vec::new();
        let mut input = io::Cursor::new(b"y\n".to_vec());
        assert_eq!(
            ask_text(&INSTALL_REMOTE, "x", &machine, &mut input, &mut out).unwrap(),
            None
        );
        assert!(out.is_empty());
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
