//! Command grammar: the `vault` command line, and the commands typed at the `vault>`
//! prompt of the vault shell. Both are parsed with clap so help and errors look alike.
//!
//! Security: no argument ever carries a master password or hidden field; those are only
//! read from hidden prompts.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use vault_core::generator::DEFAULT_PASSWORD_LENGTH;

/// Idle minutes before a session locks itself, unless `--idle-timeout` says otherwise.
pub const DEFAULT_IDLE_MINUTES: u64 = 5;

/// `vault`: a local password manager with one encrypted vault per person.
///
/// ```
/// use clap::Parser;
/// use vault_cli::args::{Cli, Command};
/// let cli = Cli::try_parse_from(["vault", "unlock", "alice"]).unwrap();
/// assert!(matches!(cli.command, Command::Unlock(_)));
/// ```
#[derive(Debug, Parser)]
#[command(name = "vault", version, about)]
pub struct Cli {
    /// Directory holding the vaults [default: the platform data directory]
    #[arg(long, global = true, value_name = "PATH")]
    pub vault_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

/// What `vault` was asked to do.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a new vault and open the vault shell on it
    Init(Open),
    /// Unlock a vault and open the vault shell on it
    Unlock(Open),
    /// Generate a random password and print it
    Gen(Gen),
}

/// Which vault to open, and how long it may stay idle.
#[derive(Debug, Args)]
pub struct Open {
    /// Name of the vault (asked for if left out)
    pub vaultname: Option<String>,

    /// Minutes without a command before the vault locks itself
    #[arg(
        long,
        value_name = "MINUTES",
        default_value_t = DEFAULT_IDLE_MINUTES,
        value_parser = clap::value_parser!(u64).range(1..=60),
    )]
    pub idle_timeout: u64,
}

/// Options of `gen`.
#[derive(Debug, Args)]
pub struct Gen {
    /// Number of characters (12-128)
    #[arg(long, value_name = "N", default_value_t = DEFAULT_PASSWORD_LENGTH)]
    pub length: usize,
}

/// One line typed at the `vault>` prompt.
///
/// ```
/// use clap::Parser;
/// use vault_cli::args::{ShellCommand, ShellLine};
/// let line = ShellLine::try_parse_from(["get", "github", "--copy"]).unwrap();
/// assert!(matches!(line.command, ShellCommand::Get { copy: true, .. }));
/// ```
#[derive(Debug, Parser)]
#[command(
    name = "vault>",
    no_binary_name = true,
    disable_version_flag = true,
    help_template = "{subcommands}",
    after_help = "Quote titles with spaces: get \"my bank\""
)]
pub struct ShellLine {
    #[command(subcommand)]
    pub command: ShellCommand,
}

/// A command of the vault shell.
#[derive(Debug, Subcommand)]
pub enum ShellCommand {
    /// Show a secret, hidden fields masked
    Get {
        /// Title of the secret
        title: String,
        /// Show the hidden fields too
        #[arg(long, conflicts_with = "copy")]
        show: bool,
        /// Copy the password to the clipboard instead of showing it
        #[arg(long)]
        copy: bool,
    },
    /// Add a secret, or replace the one with this title
    Save {
        /// Title of the secret
        title: String,
    },
    /// List all secrets, without hidden fields
    List,
    /// Remove a secret
    Rm {
        /// Title of the secret
        title: String,
    },
    /// Generate a random password
    Gen(Gen),
    /// Change the master password
    Passwd,
    /// Lock the vault and leave the shell
    #[command(visible_aliases = ["exit", "quit"])]
    Lock,
}

/// Names of the commands that only work inside the vault shell, for a helpful error
/// when one is typed at the OS shell (`vault list`).
///
/// ```
/// assert!(vault_cli::args::is_shell_only("list"));
/// assert!(!vault_cli::args::is_shell_only("gen"));
/// ```
#[must_use]
pub fn is_shell_only(name: &str) -> bool {
    matches!(
        name,
        "get" | "save" | "list" | "rm" | "passwd" | "lock" | "exit" | "quit"
    )
}
