//! Command grammar behaviour, through the public `args` API.

use clap::{Command, CommandFactory};
use vault_cli::args::{Cli, ShellLine};

/// Markers that only appear in rustdoc examples, never in hand-written help.
const DOC_EXAMPLE_MARKERS: [&str; 2] = ["```", "assert!"];

/// Collects every help text clap could print for `cmd` and its subcommands, at any depth.
///
/// Reads `about` and `long_about` directly as well as the rendered long help, so a doc
/// example is caught even when a custom `help_template` hides it today.
///
/// ```ignore
/// let texts = help_texts(&mut ShellLine::command());
/// assert!(texts.iter().any(|(name, _)| name == "vault> get"));
/// ```
fn help_texts(cmd: &mut Command) -> Vec<(String, String)> {
    fn walk(cmd: &mut Command, path: &str, out: &mut Vec<(String, String)>) {
        let path = if path.is_empty() {
            cmd.get_name().to_owned()
        } else {
            format!("{path} {}", cmd.get_name())
        };
        for text in [cmd.get_about(), cmd.get_long_about()]
            .into_iter()
            .flatten()
        {
            out.push((path.clone(), text.to_string()));
        }
        out.push((path.clone(), cmd.render_long_help().to_string()));
        for sub in cmd.get_subcommands_mut() {
            walk(sub, &path, out);
        }
    }

    cmd.build();
    let mut out = Vec::new();
    walk(cmd, "", &mut out);
    out
}

/// `vault --help` shows the summary from the doc comment, without markdown backticks.
#[test]
fn top_level_help_shows_the_plain_summary() {
    let help = Cli::command().render_long_help().to_string();
    assert!(
        help.contains("Local password manager with one encrypted vault per person"),
        "summary missing from --help:\n{help}"
    );
    assert!(!help.contains('`'), "markdown backticks in --help:\n{help}");
}

/// No help text of the `vault` command line or the vault shell contains a rustdoc example.
#[test]
fn no_help_text_contains_a_doc_example() {
    for mut cmd in [Cli::command(), ShellLine::command()] {
        for (path, text) in help_texts(&mut cmd) {
            for marker in DOC_EXAMPLE_MARKERS {
                assert!(
                    !text.contains(marker),
                    "doc example leaked into help of `{path}`:\n{text}"
                );
            }
        }
    }
}
