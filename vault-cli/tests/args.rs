//! Command grammar behaviour, through the public `args` API.

use clap::CommandFactory;
use vault_cli::args::Cli;

#[test]
fn long_help_shows_the_summary_but_not_the_doc_example() {
    let help = Cli::command().render_long_help().to_string();
    assert!(help.contains("a local password manager with one encrypted vault per person"));
    assert!(
        !help.contains("```"),
        "doc example leaked into --help:\n{help}"
    );
    assert!(
        !help.contains("try_parse_from"),
        "doc example leaked into --help:\n{help}"
    );
}
