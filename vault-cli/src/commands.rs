//! The commands of the vault shell (`get`, `save`, `list`, `rm`, `gen`, `passwd`, `lock`).
//!
//! Every command reads what it needs from the person first and only then takes the
//! session, so a prompt left waiting never holds the vault open: auto-lock can wipe it
//! meanwhile, and the command then fails with "vault is locked".
//!
//! Security:
//! - Hidden fields and master passwords are read only through hidden prompts and moved
//!   straight into `HiddenValue` / `MasterPassword`.
//! - `get --show` refuses when stdout is not a terminal, so hidden fields never end up in
//!   a pipe or a file.
//! - Error messages are fixed strings; none includes a field value.

use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use chrono::Local;
use vault_core::crypto::MasterPassword;
use vault_core::generator::{self, DEFAULT_PASSWORD_LENGTH, GeneratorError};
use vault_core::session::{CustomField, HiddenValue, Saved, Secret, Session, SessionError};
use vault_core::storage::SqliteStore;

use crate::args::ShellCommand;
use crate::clipboard::CLEAR_AFTER;
use crate::render::{self, Reveal};
use crate::terminal::{Terminal, TerminalError};

/// The session of the vault shell, shared with the auto-lock and signal threads;
/// `None` once it has been locked.
pub(crate) type SharedSession = Arc<Mutex<Option<Session<SqliteStore>>>>;

/// Whether the shell goes on after a command.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Flow {
    /// Read the next command.
    Continue,
    /// Lock the vault and leave the shell.
    Lock,
}

/// Why a command failed. Messages are fixed strings.
///
/// ```ignore
/// assert_eq!(CommandError::NoPassword.to_string(), "this secret has no password to copy");
/// ```
#[derive(Debug)]
pub(crate) enum CommandError {
    /// The session refused (wrong title, locked, invalid field, ...).
    Session(SessionError),
    /// The terminal gave no input (cancelled, closed) or failed.
    Terminal(TerminalError),
    /// No password could be generated.
    Generator(GeneratorError),
    /// `get --show` while stdout is not a terminal.
    NotATerminal,
    /// `get --copy` on a secret without a password.
    NoPassword,
    /// The two entries of a new master password differ.
    PasswordsDiffer,
}

impl CommandError {
    /// Whether the session is gone, so the shell must exit.
    ///
    /// ```ignore
    /// assert!(CommandError::Session(SessionError::Conflict).ends_session());
    /// ```
    pub(crate) fn ends_session(&self) -> bool {
        matches!(
            self,
            Self::Session(SessionError::Locked | SessionError::Conflict)
        )
    }
}

impl fmt::Display for CommandError {
    /// Writes the fixed message for this error.
    ///
    /// ```ignore
    /// assert_eq!(CommandError::PasswordsDiffer.to_string(), "master passwords don't match");
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session(err) => err.fmt(f),
            Self::Terminal(err) => err.fmt(f),
            Self::Generator(err) => err.fmt(f),
            Self::NotATerminal => {
                f.write_str("hidden fields are only shown on a terminal, not into a pipe or file")
            }
            Self::NoPassword => f.write_str("this secret has no password to copy"),
            Self::PasswordsDiffer => f.write_str("master passwords don't match"),
        }
    }
}

impl From<SessionError> for CommandError {
    /// Wraps a session failure.
    ///
    /// ```ignore
    /// let err = CommandError::from(SessionError::SecretNotFound);
    /// ```
    fn from(err: SessionError) -> Self {
        Self::Session(err)
    }
}

impl From<TerminalError> for CommandError {
    /// Wraps a terminal failure.
    ///
    /// ```ignore
    /// let err = CommandError::from(TerminalError::Interrupted);
    /// ```
    fn from(err: TerminalError) -> Self {
        Self::Terminal(err)
    }
}

impl From<GeneratorError> for CommandError {
    /// Wraps a generator failure.
    ///
    /// ```ignore
    /// let err = CommandError::from(GeneratorError::InvalidLength);
    /// ```
    fn from(err: GeneratorError) -> Self {
        Self::Generator(err)
    }
}

/// Runs one vault shell command.
///
/// ```ignore
/// let flow = commands::execute(ShellCommand::List, terminal, &session)?;
/// ```
pub(crate) fn execute(
    command: ShellCommand,
    terminal: &mut dyn Terminal,
    session: &SharedSession,
) -> Result<Flow, CommandError> {
    match command {
        ShellCommand::Get { title, show, copy } => get(terminal, session, &title, show, copy)?,
        ShellCommand::Save { title } => save(terminal, session, title)?,
        ShellCommand::List => list(terminal, session)?,
        ShellCommand::Rm { title } => remove(terminal, session, &title)?,
        ShellCommand::Gen(options) => generate(terminal, options.length)?,
        ShellCommand::Passwd => change_master_password(terminal, session)?,
        ShellCommand::Lock => return Ok(Flow::Lock),
    }
    Ok(Flow::Continue)
}

/// Asks for a new master password twice; they must match.
///
/// ```ignore
/// let password = commands::new_master_password(terminal, "New master password: ")?;
/// ```
pub(crate) fn new_master_password(
    terminal: &mut dyn Terminal,
    prompt: &str,
) -> Result<MasterPassword, CommandError> {
    let mut first = terminal.read_hidden(prompt)?;
    let second = terminal.read_hidden("Repeat master password: ")?;
    if *first != *second {
        return Err(CommandError::PasswordsDiffer);
    }
    Ok(MasterPassword::new(std::mem::take(&mut *first)))
}

/// `get`: prints a secret masked, with `--show` unmasked, or with `--copy` copies its
/// password to the clipboard instead.
///
/// ```ignore
/// get(terminal, session, "github", false, true)?; // copy
/// ```
fn get(
    terminal: &mut dyn Terminal,
    session: &SharedSession,
    title: &str,
    show: bool,
    copy: bool,
) -> Result<(), CommandError> {
    if copy {
        with_session(session, |session| {
            let password = session
                .get(title)?
                .password()
                .ok_or(CommandError::NoPassword)?;
            Ok(terminal.copy_to_clipboard(password)?)
        })?;
        terminal.print(&format!(
            "password copied; the clipboard clears in {} seconds",
            CLEAR_AFTER.as_secs()
        ));
        return Ok(());
    }
    if show && !terminal.stdout_is_terminal() {
        return Err(CommandError::NotATerminal);
    }
    let reveal = if show { Reveal::Shown } else { Reveal::Masked };
    let view = with_session(session, |session| {
        Ok(render::secret(session.get(title)?, reveal, &Local))
    })?;
    terminal.print(&view);
    Ok(())
}

/// `save`: asks for each field, then adds the secret, or replaces the one with this
/// title after confirming. An empty password is generated.
///
/// ```ignore
/// save(terminal, session, "github".into())?;
/// ```
fn save(
    terminal: &mut dyn Terminal,
    session: &SharedSession,
    title: String,
) -> Result<(), CommandError> {
    let exists = with_session(session, |session| Ok(session.contains(&title)?))?;
    if exists {
        let question = format!(
            "Replace existing secret '{}'?",
            render::escape(&title, false).as_str()
        );
        if !confirm(terminal, &question)? {
            terminal.print("not saved");
            return Ok(());
        }
    }
    let mut secret = Secret::new(title);
    if let Some(username) = optional_line(terminal, "Username (optional): ")? {
        secret = secret.with_username(username);
    }
    let mut typed = terminal.read_hidden("Password (empty to generate): ")?;
    let generated = typed.is_empty();
    let password = if generated {
        generator::generate_password(DEFAULT_PASSWORD_LENGTH)?
    } else {
        HiddenValue::new(std::mem::take(&mut *typed))
    };
    secret = secret.with_password(password);
    if let Some(url) = optional_line(terminal, "URL (optional): ")? {
        secret = secret.with_url(url);
    }
    if let Some(notes) = optional_line(terminal, "Notes (optional): ")? {
        secret = secret.with_notes(notes);
    }
    if let Some(tags) = optional_line(terminal, "Tags (comma-separated, optional): ")? {
        for tag in tags.split(',').map(str::trim).filter(|tag| !tag.is_empty()) {
            secret = secret.with_tag(tag);
        }
    }
    while confirm(terminal, "Add a custom field?")? {
        let Some(name) = optional_line(terminal, "Field name: ")? else {
            break;
        };
        let field = if confirm(terminal, "Hidden?")? {
            let mut value = terminal.read_hidden("Value: ")?;
            CustomField::hidden(name, HiddenValue::new(std::mem::take(&mut *value)))
        } else {
            CustomField::plain(
                name,
                optional_line(terminal, "Value: ")?.unwrap_or_default(),
            )
        };
        secret = secret.with_custom_field(field);
    }

    let saved = with_session(session, |session| Ok(session.save(secret)?))?;
    if generated {
        terminal.print(&format!(
            "generated a {DEFAULT_PASSWORD_LENGTH}-character password; `get <title> --copy` copies it"
        ));
    }
    terminal.print(match saved {
        Saved::Added => "secret added",
        Saved::Replaced => "secret replaced",
    });
    Ok(())
}

/// `list`: prints the table of all secrets.
///
/// ```ignore
/// list(terminal, session)?;
/// ```
fn list(terminal: &mut dyn Terminal, session: &SharedSession) -> Result<(), CommandError> {
    let table = with_session(session, |session| Ok(render::secret_list(&session.list()?)))?;
    terminal.print(&table);
    Ok(())
}

/// `rm`: removes a secret after confirming.
///
/// ```ignore
/// remove(terminal, session, "github")?;
/// ```
fn remove(
    terminal: &mut dyn Terminal,
    session: &SharedSession,
    title: &str,
) -> Result<(), CommandError> {
    if !with_session(session, |session| Ok(session.contains(title)?))? {
        return Err(SessionError::SecretNotFound.into());
    }
    let question = format!("Remove secret '{}'?", render::escape(title, false).as_str());
    if !confirm(terminal, &question)? {
        terminal.print("not removed");
        return Ok(());
    }
    with_session(session, |session| Ok(session.remove(title)?))?;
    terminal.print("secret removed");
    Ok(())
}

/// `gen`: prints a new random password and offers to copy it.
///
/// ```ignore
/// generate(terminal, 24)?;
/// ```
fn generate(terminal: &mut dyn Terminal, length: usize) -> Result<(), CommandError> {
    let password = generator::generate_password(length)?;
    terminal.print(password.reveal());
    if confirm(terminal, "Copy to clipboard?")? {
        terminal.copy_to_clipboard(&password)?;
        terminal.print(&format!(
            "copied; the clipboard clears in {} seconds",
            CLEAR_AFTER.as_secs()
        ));
    }
    Ok(())
}

/// `passwd`: changes the master password after checking the current one.
///
/// ```ignore
/// change_master_password(terminal, session)?;
/// ```
fn change_master_password(
    terminal: &mut dyn Terminal,
    session: &SharedSession,
) -> Result<(), CommandError> {
    let mut current = terminal.read_hidden("Current master password: ")?;
    let current = MasterPassword::new(std::mem::take(&mut *current));
    let new = new_master_password(terminal, "New master password: ")?;
    with_session(session, |session| {
        Ok(session.change_master_password(&current, &new)?)
    })?;
    terminal.print("master password changed");
    Ok(())
}

/// Runs `f` on the open session; [`SessionError::Locked`] once it has been locked.
///
/// ```ignore
/// let table = with_session(session, |s| Ok(render::secret_list(&s.list()?)))?;
/// ```
fn with_session<R>(
    session: &SharedSession,
    f: impl FnOnce(&mut Session<SqliteStore>) -> Result<R, CommandError>,
) -> Result<R, CommandError> {
    let mut guard = session.lock().unwrap_or_else(PoisonError::into_inner);
    let session = guard.as_mut().ok_or(SessionError::Locked)?;
    f(session)
}

/// Asks a yes/no question; only `y` or `yes` counts as yes.
///
/// ```ignore
/// if confirm(terminal, "Remove secret 'github'?")? { /* ... */ }
/// ```
fn confirm(terminal: &mut dyn Terminal, question: &str) -> Result<bool, TerminalError> {
    let answer = terminal.read_line(&format!("{question} [y/N] "))?;
    Ok(matches!(answer.trim().to_lowercase().as_str(), "y" | "yes"))
}

/// Reads a visible line; `None` if it is empty after trimming.
///
/// ```ignore
/// let username = optional_line(terminal, "Username (optional): ")?;
/// ```
fn optional_line(
    terminal: &mut dyn Terminal,
    prompt: &str,
) -> Result<Option<String>, TerminalError> {
    let line = terminal.read_line(prompt)?;
    let trimmed = line.trim();
    Ok((!trimmed.is_empty()).then(|| trimmed.to_owned()))
}
