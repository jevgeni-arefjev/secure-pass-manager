//! The commands of the vault shell (`get`, `save`, `list`, `rm`, `gen`, `passwd`,
//! `backup`, `log`, `lock`).
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
//! - `get --show` and `get --copy` go through `Session::reveal`, so every reveal is in
//!   the audit log; a masked `get` is not.
//! - Error messages are fixed strings; none includes a field value.

use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use chrono::Local;
use vault_core::backup::Destination;
use vault_core::crypto::MasterPassword;
use vault_core::generator::{self, DEFAULT_PASSWORD_LENGTH, GeneratorError};
use vault_core::session::{
    CustomField, FieldProblem, FieldValue, HiddenValue, Saved, Secret, Session, SessionError,
    check, check_master_password,
};
use vault_core::storage::FileStore;
use zeroize::Zeroizing;

use crate::args::ShellCommand;
use crate::clipboard::CLEAR_AFTER;
use crate::render::{self, Reveal};
use crate::terminal::{Terminal, TerminalError};

/// The session of the vault shell, shared with the auto-lock and signal threads;
/// `None` once it has been locked.
pub(crate) type SharedSession = Arc<Mutex<Option<Session<FileStore>>>>;

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
    /// A field given with the command (the title of `save`) breaks a rule.
    InvalidField(FieldProblem),
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
    /// Writes the fixed message for this error; a refused save lists every problem, one
    /// per line ([`render::invalid_secret`]).
    ///
    /// ```ignore
    /// assert_eq!(CommandError::PasswordsDiffer.to_string(), "master passwords don't match");
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session(SessionError::InvalidSecret(invalid)) => {
                f.write_str(&render::invalid_secret(invalid))
            }
            Self::Session(err) => err.fmt(f),
            Self::InvalidField(problem) => f.write_str(&render::refused_field(problem)),
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

/// Runs one vault shell command. `vault_dir` is the vault directory the session's
/// vault lives in; `backup` refuses destinations inside it.
///
/// ```ignore
/// let flow = commands::execute(ShellCommand::List, terminal, &session, &vault_dir)?;
/// ```
pub(crate) fn execute(
    command: ShellCommand,
    terminal: &mut dyn Terminal,
    session: &SharedSession,
    vault_dir: &Path,
) -> Result<Flow, CommandError> {
    match command {
        ShellCommand::Get { title, show, copy } => get(terminal, session, &title, show, copy)?,
        ShellCommand::Save { title } => save(terminal, session, title)?,
        ShellCommand::List => list(terminal, session)?,
        ShellCommand::Rm { title } => remove(terminal, session, &title)?,
        ShellCommand::Gen(options) => generate(terminal, options.length)?,
        ShellCommand::Passwd => change_master_password(terminal, session)?,
        ShellCommand::Backup { path } => backup(terminal, session, vault_dir, &path)?,
        ShellCommand::Log { limit } => log(terminal, session, limit.into())?,
        ShellCommand::Lock => return Ok(Flow::Lock),
    }
    Ok(Flow::Continue)
}

/// Asks for a new master password, checks its strength at once, then asks for it
/// again; the two entries must match.
///
/// A weak password fails with `CommandError::Session(SessionError::WeakMasterPassword)`
/// before the repeat prompt, so the user doesn't type it twice for nothing.
///
/// Security: both entries move straight into locked [`MasterPassword`]s (no extra plain
/// copy) and are compared there.
///
/// ```ignore
/// let password = commands::new_master_password(terminal, "New master password: ")?;
/// ```
pub(crate) fn new_master_password(
    terminal: &mut dyn Terminal,
    prompt: &str,
) -> Result<MasterPassword, CommandError> {
    let mut first = terminal.read_hidden(prompt)?;
    let password = MasterPassword::new(std::mem::take(&mut *first));
    check_master_password(&password).map_err(SessionError::from)?;
    let mut repeat = terminal.read_hidden("Repeat master password: ")?;
    let repeat = MasterPassword::new(std::mem::take(&mut *repeat));
    if !password.matches(&repeat) {
        return Err(CommandError::PasswordsDiffer);
    }
    Ok(password)
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
            session.reveal(title, |secret| {
                let password = secret.password().ok_or(CommandError::NoPassword)?;
                Ok(terminal.copy_to_clipboard(password)?)
            })
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
    let view = with_session(session, |session| {
        if show {
            session.reveal(title, |secret| {
                Ok::<_, CommandError>(render::secret(secret, Reveal::Shown, &Local))
            })
        } else {
            Ok(render::secret(session.get(title)?, Reveal::Masked, &Local))
        }
    })?;
    terminal.print(&view);
    Ok(())
}

/// `save`: checks the title, then asks for each field, re-asking an answer until it
/// passes the core's per-field checks ([`check`]); then adds the secret, or replaces
/// the one with this title after confirming. An empty password is generated; an empty
/// optional standard field (username, URL, notes, tags) is left unset. Ctrl-C at any
/// prompt cancels the save and nothing is written.
///
/// Security: hidden answers are only read through hidden prompts, and a refused answer
/// is reported by its rule ([`render::field_problem`]), never echoed.
///
/// ```ignore
/// save(terminal, session, "github".into())?;
/// ```
fn save(
    terminal: &mut dyn Terminal,
    session: &SharedSession,
    title: String,
) -> Result<(), CommandError> {
    check::title(&title).map_err(CommandError::InvalidField)?;
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
    if let Some(username) = checked_line(terminal, "Username (optional): ", check::username)? {
        secret = secret.with_username(username);
    }
    let typed = ask_password(terminal)?;
    let generated = typed.is_none();
    let password = match typed {
        Some(password) => password,
        None => generator::generate_password(DEFAULT_PASSWORD_LENGTH)?,
    };
    secret = secret.with_password(password);
    if let Some(url) = checked_line(terminal, "URL (optional): ", check::url)? {
        secret = secret.with_url(url);
    }
    if let Some(notes) = checked_line(terminal, "Notes (optional): ", check::notes)? {
        secret = secret.with_notes(notes);
    }
    for tag in ask_tags(terminal)? {
        secret = secret.with_tag(tag);
    }
    for field in ask_custom_fields(terminal)? {
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

/// Asks with `ask` until `find_problems` finds nothing wrong with the answer, printing each
/// problem (`vault: <field>: <rule>`) before asking again. A terminal error (Ctrl-C,
/// end of input) ends the loop.
///
/// Security: only the rule is printed, never the refused answer.
///
/// ```ignore
/// let url = ask_until_valid(
///     terminal,
///     |terminal| Ok(optional_line(terminal, "URL (optional): ")?),
///     |url| if_given(url.as_deref(), check::url),
/// )?;
/// ```
fn ask_until_valid<T>(
    terminal: &mut dyn Terminal,
    mut ask: impl FnMut(&mut dyn Terminal) -> Result<T, CommandError>,
    find_problems: impl Fn(&T) -> Vec<FieldProblem>,
) -> Result<T, CommandError> {
    loop {
        let answer = ask(terminal)?;
        let found = find_problems(&answer);
        if found.is_empty() {
            return Ok(answer);
        }
        for problem in &found {
            terminal.print_error(&format!("vault: {}", render::field_problem(problem)));
        }
    }
}

/// Asks for an optional visible field until it is left empty (`None`) or passes
/// `check`.
///
/// ```ignore
/// let url = checked_line(terminal, "URL (optional): ", check::url)?;
/// ```
fn checked_line(
    terminal: &mut dyn Terminal,
    prompt: &str,
    check: fn(&str) -> Result<(), FieldProblem>,
) -> Result<Option<String>, CommandError> {
    ask_until_valid(
        terminal,
        |terminal| Ok(optional_line(terminal, prompt)?),
        |answer| if_given(answer.as_deref(), check),
    )
}

/// Asks for the password through a hidden prompt until it is left empty (`None`: to be
/// generated) or passes [`check::password`].
///
/// ```ignore
/// let typed = ask_password(terminal)?;
/// ```
fn ask_password(terminal: &mut dyn Terminal) -> Result<Option<HiddenValue>, CommandError> {
    ask_until_valid(
        terminal,
        |terminal| {
            let mut typed = terminal.read_hidden("Password (empty to generate): ")?;
            Ok((!typed.is_empty()).then(|| HiddenValue::new(std::mem::take(&mut *typed))))
        },
        |typed| if_given(typed.as_ref(), check::password),
    )
}

/// Asks for the comma-separated tags until every one passes [`check::tag`] against the
/// tags before it on the line. Blank entries are dropped; an empty line means no tags.
///
/// ```ignore
/// for tag in ask_tags(terminal)? { secret = secret.with_tag(tag); }
/// ```
fn ask_tags(terminal: &mut dyn Terminal) -> Result<Vec<String>, CommandError> {
    ask_until_valid(
        terminal,
        |terminal| {
            let line = optional_line(terminal, "Tags (comma-separated, optional): ")?;
            Ok(line.as_deref().map_or_else(Vec::new, |line| {
                line.split(',')
                    .map(str::trim)
                    .filter(|tag| !tag.is_empty())
                    .map(str::to_owned)
                    .collect()
            }))
        },
        |tags| {
            tags.iter()
                .enumerate()
                .filter_map(|(i, tag)| check::tag(tag, &tags[..i]).err())
                .collect()
        },
    )
}

/// Asks for custom fields while the person wants more: a name checked against the
/// fields before it ([`check::custom_field_name`]; an empty name stops), whether it is
/// hidden, then a value ([`check::custom_field_value`]; an empty one is asked again).
///
/// Security: a hidden value is read through a hidden prompt and moved straight into a
/// [`HiddenValue`].
///
/// ```ignore
/// for field in ask_custom_fields(terminal)? { secret = secret.with_custom_field(field); }
/// ```
fn ask_custom_fields(terminal: &mut dyn Terminal) -> Result<Vec<CustomField>, CommandError> {
    let mut fields: Vec<CustomField> = Vec::new();
    while confirm(terminal, "Add a custom field?")? {
        let name = ask_until_valid(
            terminal,
            |terminal| Ok(optional_line(terminal, "Field name: ")?),
            |name| {
                if_given(name.as_deref(), |name| {
                    check::custom_field_name(name, &fields)
                })
            },
        )?;
        let Some(name) = name else {
            break;
        };
        let hidden = confirm(terminal, "Hidden?")?;
        let value = ask_until_valid(
            terminal,
            |terminal| {
                Ok(if hidden {
                    let mut value = terminal.read_hidden("Value: ")?;
                    FieldValue::Hidden(HiddenValue::new(std::mem::take(&mut *value)))
                } else {
                    let mut value = terminal.read_line("Value: ")?;
                    FieldValue::Plain(Zeroizing::new(std::mem::take(&mut *value)))
                })
            },
            |value| as_problems(check::custom_field_value(value, &fields)),
        )?;
        fields.push(CustomField::new(name, value));
    }
    Ok(fields)
}

/// The problem of a single-field check as a list: empty if it passed.
///
/// ```ignore
/// assert!(as_problems(check::title("GitHub")).is_empty());
/// ```
fn as_problems(checked: Result<(), FieldProblem>) -> Vec<FieldProblem> {
    checked.err().into_iter().collect()
}

/// The problems `check` finds in an optional answer; none if it was left empty
/// (`None`: "not set").
///
/// ```ignore
/// assert!(if_given(None, check::url).is_empty());
/// ```
fn if_given<T: ?Sized>(
    answer: Option<&T>,
    check: impl FnOnce(&T) -> Result<(), FieldProblem>,
) -> Vec<FieldProblem> {
    answer.map_or_else(Vec::new, |answer| as_problems(check(answer)))
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

/// `backup`: writes a verified ciphertext copy of the vault to the new file `path`,
/// outside `vault_dir`, and says which revision it holds.
///
/// ```ignore
/// backup(terminal, session, &vault_dir, Path::new("/media/usb/alice.vault"))?;
/// ```
fn backup(
    terminal: &mut dyn Terminal,
    session: &SharedSession,
    vault_dir: &Path,
    path: &Path,
) -> Result<(), CommandError> {
    let dest = Destination::new(path, vault_dir).map_err(SessionError::from)?;
    let revision = with_session(session, |session| Ok(session.backup(&dest)?))?;
    terminal.print(&format!(
        "Backup written to {} (revision {revision}). It opens with the master password this vault has now.",
        render::escape(&path.to_string_lossy(), false).as_str()
    ));
    Ok(())
}

/// `log`: prints up to `limit` audit events of this vault, newest first, in local time.
///
/// ```ignore
/// log(terminal, session, 20)?;
/// ```
fn log(
    terminal: &mut dyn Terminal,
    session: &SharedSession,
    limit: usize,
) -> Result<(), CommandError> {
    let lines = with_session(session, |session| Ok(session.audit_log(limit)?))?;
    terminal.print(&render::audit_log(&lines, &Local));
    Ok(())
}

/// Runs `f` on the open session; [`SessionError::Locked`] once it has been locked.
///
/// ```ignore
/// let table = with_session(session, |s| Ok(render::secret_list(&s.list()?)))?;
/// ```
fn with_session<R>(
    session: &SharedSession,
    f: impl FnOnce(&mut Session<FileStore>) -> Result<R, CommandError>,
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
