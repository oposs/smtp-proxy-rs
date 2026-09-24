//! The manual's OPTIONS section against the flags clap knows (spec
//! `2026-09-23-manual-design.md`, section 8).
//!
//! The flag set comes from `Cli::command()`, not from the rendered `--help`
//! text, so a change of clap's help layout cannot break this test, and a flag
//! added to `Cli` without an entry in `docs/manual.md` turns it red.
//!
//! An entry is a bullet whose first paragraph opens with an inline code span
//! immediately followed by a colon, the shape repo-infra's
//! `build/man-deflist.lua` turns into a `.TP` term:
//!
//! ```text
//! - `--max_connections <n>`: Concurrent connections in total. Default: 1000.
//! ```
use clap::{Arg, ArgAction, Command, CommandFactory};
use smtp_proxy::config::Cli;

const MANUAL: &str = include_str!("../docs/manual.md");

/// How an entry states a clap default. One fixed sentence, so the check is a
/// substring match rather than a reading of the prose.
fn default_sentence(value: &str) -> String {
    format!("Default: {value}.")
}

/// What an entry may say when clap has no default.
const NO_DEFAULT: &str = "Default: none.";

/// One bullet of the OPTIONS section.
struct Entry {
    /// The flag spellings of the code-span term, for example `-h` and `--help`.
    flags: Vec<String>,
    /// The description, with continuation lines joined by single spaces.
    text: String,
}

/// One argument as clap knows it.
struct Flag {
    names: Vec<String>,
    /// `None` for a switch, whose implicit `false` is no operator-visible
    /// default, and for a value flag without a default.
    default: Option<String>,
}

/// From `# OPTIONS` to the next level-1 heading; empty when there is none.
fn options_section(manual: &str) -> &str {
    const HEADING: &str = "\n# OPTIONS\n";
    let Some(at) = manual.find(HEADING) else {
        return "";
    };
    let rest = &manual[at + HEADING.len()..];
    &rest[..rest.find("\n# ").unwrap_or(rest.len())]
}

/// The term and the text of an entry line, `` - `term`: text ``; `None` for
/// any other line, including a bullet in another shape.
fn entry_line(line: &str) -> Option<(&str, &str)> {
    let rest = line.strip_prefix("- `")?;
    let (term, after) = rest.split_once('`')?;
    let text = after.strip_prefix(':')?;
    Some((term, text))
}

/// The entries of `section`. A term may list several spellings separated by
/// `, ` (`` `-h, --help` ``); only the first word of each counts, so a value
/// name (`<n>`) does not.
fn entries(section: &str) -> Vec<Entry> {
    let mut out: Vec<Entry> = Vec::new();
    let mut open = false;
    for line in section.lines() {
        if let Some((term, text)) = entry_line(line) {
            let flags = term
                .split(", ")
                .filter_map(|t| t.split_whitespace().next())
                .map(str::to_string)
                .collect();
            out.push(Entry {
                flags,
                text: text.trim().to_string(),
            });
            open = true;
        } else if open && line.starts_with("  ") {
            if let Some(last) = out.last_mut() {
                last.text.push(' ');
                last.text.push_str(line.trim());
            }
        } else if !line.trim().is_empty() {
            open = false;
        }
    }
    out
}

fn flag(arg: &Arg) -> Flag {
    let mut names = Vec::new();
    if let Some(short) = arg.get_short() {
        names.push(format!("-{short}"));
    }
    if let Some(long) = arg.get_long() {
        names.push(format!("--{long}"));
    }
    let default = arg
        .get_action()
        .takes_values()
        .then(|| {
            arg.get_default_values()
                .iter()
                .map(|v| v.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(",")
        })
        .filter(|d| !d.is_empty());
    Flag { names, default }
}

fn clap_flags(cmd: &Command) -> Vec<Flag> {
    cmd.get_arguments().map(flag).collect()
}

/// Every disagreement between `manual` and `cmd`, each naming its flag.
fn problems(manual: &str, cmd: &Command) -> Vec<String> {
    let section = options_section(manual);
    if section.is_empty() {
        return vec!["the manual has no `# OPTIONS` section".to_string()];
    }
    let entries = entries(section);
    let flags = clap_flags(cmd);
    let mut out = Vec::new();
    for flag in &flags {
        let shown = flag.names.join(", ");
        let Some(entry) = entries
            .iter()
            .find(|e| flag.names.iter().any(|n| e.flags.contains(n)))
        else {
            out.push(format!("{shown} has no entry in OPTIONS"));
            continue;
        };
        for name in &flag.names {
            if !entry.flags.contains(name) {
                out.push(format!("the entry for {shown} does not name {name}"));
            }
        }
        match &flag.default {
            Some(value) if !entry.text.contains(&default_sentence(value)) => out.push(format!(
                "{shown}: clap's default is {value:?}, and the entry lacks {:?}",
                default_sentence(value)
            )),
            None if entry.text.replace(NO_DEFAULT, "").contains("Default: ") => out.push(format!(
                "{shown}: the entry states a default, and clap has none"
            )),
            _ => {}
        }
    }
    for entry in &entries {
        for name in &entry.flags {
            if !flags.iter().any(|f| f.names.contains(name)) {
                out.push(format!("OPTIONS has {name}, which clap does not know"));
            }
        }
    }
    out
}

fn cli() -> Command {
    let mut cmd = Cli::command();
    cmd.build();
    cmd
}

#[test]
fn the_manual_documents_every_flag() {
    let found = problems(MANUAL, &cli());
    assert!(
        found.is_empty(),
        "docs/manual.md OPTIONS disagrees with clap:\n  {}",
        found.join("\n  ")
    );
}

/// Keeps the test above from passing because one side read as empty.
#[test]
fn both_sides_are_read() {
    let cmd = cli();
    let flags = clap_flags(&cmd);
    assert!(flags.len() >= 24, "clap reports {} arguments", flags.len());
    let found = entries(options_section(MANUAL));
    assert!(found.len() >= 24, "OPTIONS yields {} entries", found.len());
    let max = flags
        .iter()
        .find(|f| f.names == ["--max_header_size"])
        .expect("clap knows --max_header_size");
    assert_eq!(max.default.as_deref(), Some("1048576"));
}

// --- the checker itself, against a toy command, so each rule is seen to fail

fn toy() -> Command {
    let mut cmd = Command::new("toy")
        .disable_help_flag(true)
        .arg(Arg::new("alpha").long("alpha").default_value("7"))
        .arg(Arg::new("beta").long("beta").action(ArgAction::SetTrue))
        .arg(
            Arg::new("help")
                .short('h')
                .long("help")
                .action(ArgAction::Help),
        );
    cmd.build();
    cmd
}

/// A group heading, an entry wrapped over three lines with its default
/// sentence broken across two, an entry saying `Default: none.`, and an
/// EXIT STATUS bullet after OPTIONS that must not be read as an option.
const TOY: &str = "---
title: TOY
---

# NAME

toy - a toy

# OPTIONS

## Group

- `--alpha <n>`: Alpha, wrapped
  over lines. Default:
  7.

- `--beta`: Beta. Default: none.

- `-h, --help`: Help.

# EXIT STATUS

- `0`: Success.
";

/// `TOY` with one edit, which must actually change it.
fn toy_with(from: &str, to: &str) -> String {
    let edited = TOY.replace(from, to);
    assert_ne!(edited, TOY, "the edit {from:?} changed nothing");
    edited
}

fn assert_named(manual: &str, needle: &str) {
    let found = problems(manual, &toy());
    assert!(
        found.iter().any(|p| p.contains(needle)),
        "expected a problem containing {needle:?}, got {found:?}"
    );
}

#[test]
fn a_well_formed_manual_has_no_problems() {
    assert_eq!(problems(TOY, &toy()), Vec::<String>::new());
}

#[test]
fn a_flag_without_an_entry_is_named() {
    assert_named(
        &toy_with("- `--beta`: Beta. Default: none.\n\n", ""),
        "--beta has no entry in OPTIONS",
    );
}

/// The shape the filter no longer converts, `**--x** — text`, and a code
/// span without its colon, must not pass as entries.
#[test]
fn an_entry_in_another_shape_is_not_accepted() {
    assert_named(
        &toy_with("- `--beta`: Beta.", "- **--beta** \u{2014} Beta."),
        "--beta has no entry in OPTIONS",
    );
    assert_named(
        &toy_with("- `--beta`: Beta.", "- `--beta` Beta."),
        "--beta has no entry in OPTIONS",
    );
}

#[test]
fn an_entry_clap_does_not_know_is_named() {
    assert_named(
        &toy_with(
            "Default: none.\n",
            "Default: none.\n\n- `--gamma`: Gamma.\n",
        ),
        "OPTIONS has --gamma, which clap does not know",
    );
}

#[test]
fn a_wrong_default_is_named() {
    assert_named(
        &toy_with("  7.", "  8."),
        "--alpha: clap's default is \"7\"",
    );
}

#[test]
fn a_default_clap_does_not_have_is_named() {
    assert_named(
        &toy_with("Default: none.", "Default: on."),
        "--beta: the entry states a default, and clap has none",
    );
}

#[test]
fn a_missing_short_spelling_is_named() {
    assert_named(
        &toy_with("- `-h, --help`:", "- `--help`:"),
        "the entry for -h, --help does not name -h",
    );
}

#[test]
fn a_manual_without_options_is_named() {
    assert_eq!(
        problems("# NAME\n\ntoy\n", &toy()),
        vec!["the manual has no `# OPTIONS` section".to_string()]
    );
}
