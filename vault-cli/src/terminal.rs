//! Everything the CLI reads from or writes to the person, behind one [`Terminal`] trait,
//! so the vault shell can be driven by a scripted fake in tests.
//!
//! [`StdTerminal`] is the real one: `rustyline` for visible lines (command history kept
//! in memory only, never written to a file) and our own masked prompt for hidden input
//! (ADR-0008).

mod masked;

use std::fmt;
use std::io::{self, IsTerminal, Write};

use rustyline::DefaultEditor;
use rustyline::config::Config;
use rustyline::error::ReadlineError;
use zeroize::Zeroizing;

/// Most commands kept in the in-memory history of one vault shell.
const MAX_HISTORY: usize = 200;

/// Why a read from the terminal returned no input. Messages are fixed strings.
///
/// ```
/// use vault_cli::terminal::TerminalError;
/// assert_eq!(TerminalError::NotATerminal.to_string(), "hidden input needs a terminal");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalError {
    /// Ctrl-C: cancel what is being asked.
    Interrupted,
    /// Ctrl-D, or stdin closed.
    EndOfInput,
    /// A hidden prompt was asked for while stdin is not a terminal.
    NotATerminal,
    /// A paste into a hidden prompt held a line break; nothing was taken from it.
    MultilinePaste,
    /// Reading or writing the terminal failed.
    Io,
}

impl fmt::Display for TerminalError {
    /// Writes the fixed message for this error.
    ///
    /// ```
    /// # use vault_cli::terminal::TerminalError;
    /// assert_eq!(TerminalError::Interrupted.to_string(), "cancelled");
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Interrupted => "cancelled",
            Self::EndOfInput => "end of input",
            Self::NotATerminal => "hidden input needs a terminal",
            Self::MultilinePaste => "pasted text held a line break; nothing was entered",
            Self::Io => "terminal input or output failed",
        })
    }
}

impl std::error::Error for TerminalError {}

impl From<io::Error> for TerminalError {
    /// Any I/O failure on the terminal; the OS error is dropped so nothing leaks.
    ///
    /// ```
    /// # use vault_cli::terminal::TerminalError;
    /// let err = TerminalError::from(std::io::Error::other("broken pipe"));
    /// assert_eq!(err, TerminalError::Io);
    /// ```
    fn from(_: io::Error) -> Self {
        Self::Io
    }
}

impl From<ReadlineError> for TerminalError {
    /// Maps rustyline's Ctrl-C and Ctrl-D; everything else is an I/O failure.
    ///
    /// ```
    /// # use vault_cli::terminal::TerminalError;
    /// # use rustyline::error::ReadlineError;
    /// assert_eq!(TerminalError::from(ReadlineError::Eof), TerminalError::EndOfInput);
    /// ```
    fn from(err: ReadlineError) -> Self {
        match err {
            ReadlineError::Interrupted => Self::Interrupted,
            ReadlineError::Eof => Self::EndOfInput,
            _ => Self::Io,
        }
    }
}

/// The person's terminal, as the CLI uses it.
///
/// Security: hidden input only ever comes through [`Terminal::read_hidden`]; visible
/// reads must never be used for a master password or hidden field.
///
/// ```ignore
/// let title = terminal.read_line("Title: ")?;
/// let password = HiddenValue::new(std::mem::take(&mut *terminal.read_hidden("Password: ")?));
/// terminal.print("saved");
/// ```
pub trait Terminal {
    /// Reads one vault shell command, which is kept in the in-memory history.
    fn read_command(&mut self, prompt: &str) -> Result<Zeroizing<String>, TerminalError>;

    /// Reads one visible line (a field value, a yes/no answer); not kept in the history.
    fn read_line(&mut self, prompt: &str) -> Result<Zeroizing<String>, TerminalError>;

    /// Reads one hidden line, echoing a `*` per character (ADR-0008).
    fn read_hidden(&mut self, prompt: &str) -> Result<Zeroizing<String>, TerminalError>;

    /// Writes `text` and a newline to stdout.
    fn print(&mut self, text: &str);

    /// Writes `text` and a newline to stderr.
    fn print_error(&mut self, text: &str);

    /// Whether stdout is a terminal; hidden fields are only revealed when it is.
    fn stdout_is_terminal(&self) -> bool;
}

/// The real terminal: stdin, stdout and stderr of this process.
///
/// ```no_run
/// use vault_cli::terminal::{StdTerminal, Terminal};
/// let mut terminal = StdTerminal::new()?;
/// terminal.print("hello");
/// # Ok::<(), vault_cli::terminal::TerminalError>(())
/// ```
pub struct StdTerminal {
    editor: DefaultEditor,
}

impl StdTerminal {
    /// Sets up line editing with an in-memory history of [`MAX_HISTORY`] commands.
    ///
    /// ```no_run
    /// let terminal = vault_cli::terminal::StdTerminal::new()?;
    /// # Ok::<(), vault_cli::terminal::TerminalError>(())
    /// ```
    pub fn new() -> Result<Self, TerminalError> {
        let config = Config::builder()
            .auto_add_history(false)
            .max_history_size(MAX_HISTORY)?
            .build();
        Ok(Self {
            editor: DefaultEditor::with_config(config)?,
        })
    }

    /// The underlying line editor, for the vault shell to print messages above the
    /// prompt from another thread (auto-lock).
    ///
    /// ```ignore
    /// let printer = terminal.editor_mut().create_external_printer()?;
    /// ```
    pub fn editor_mut(&mut self) -> &mut DefaultEditor {
        &mut self.editor
    }
}

impl Terminal for StdTerminal {
    /// Reads a command with line editing and adds it to the in-memory history.
    ///
    /// ```no_run
    /// # use vault_cli::terminal::{StdTerminal, Terminal};
    /// # let mut terminal = StdTerminal::new()?;
    /// let line = terminal.read_command("vault> ")?;
    /// # Ok::<(), vault_cli::terminal::TerminalError>(())
    /// ```
    fn read_command(&mut self, prompt: &str) -> Result<Zeroizing<String>, TerminalError> {
        let line = Zeroizing::new(self.editor.readline(prompt)?);
        if !line.trim().is_empty() {
            self.editor.add_history_entry(line.as_str())?;
        }
        Ok(line)
    }

    /// Reads a line with line editing, without touching the history.
    ///
    /// ```no_run
    /// # use vault_cli::terminal::{StdTerminal, Terminal};
    /// # let mut terminal = StdTerminal::new()?;
    /// let username = terminal.read_line("Username: ")?;
    /// # Ok::<(), vault_cli::terminal::TerminalError>(())
    /// ```
    fn read_line(&mut self, prompt: &str) -> Result<Zeroizing<String>, TerminalError> {
        Ok(Zeroizing::new(self.editor.readline(prompt)?))
    }

    /// Reads a masked line; refuses when stdin is not a terminal.
    ///
    /// ```no_run
    /// # use vault_cli::terminal::{StdTerminal, Terminal};
    /// # let mut terminal = StdTerminal::new()?;
    /// let typed = terminal.read_hidden("Master password: ")?;
    /// # Ok::<(), vault_cli::terminal::TerminalError>(())
    /// ```
    fn read_hidden(&mut self, prompt: &str) -> Result<Zeroizing<String>, TerminalError> {
        masked::read_masked(prompt)
    }

    /// Prints to stdout; a closed stdout is ignored, as there is nobody to tell.
    ///
    /// ```no_run
    /// # use vault_cli::terminal::{StdTerminal, Terminal};
    /// # let mut terminal = StdTerminal::new()?;
    /// terminal.print("secret saved");
    /// # Ok::<(), vault_cli::terminal::TerminalError>(())
    /// ```
    fn print(&mut self, text: &str) {
        let _ = writeln!(io::stdout(), "{text}");
    }

    /// Prints to stderr; a closed stderr is ignored.
    ///
    /// ```no_run
    /// # use vault_cli::terminal::{StdTerminal, Terminal};
    /// # let mut terminal = StdTerminal::new()?;
    /// terminal.print_error("vault: no secret with this title");
    /// # Ok::<(), vault_cli::terminal::TerminalError>(())
    /// ```
    fn print_error(&mut self, text: &str) {
        let _ = writeln!(io::stderr(), "{text}");
    }

    /// Checks stdout with `isatty`.
    ///
    /// ```no_run
    /// # use vault_cli::terminal::{StdTerminal, Terminal};
    /// # let terminal = StdTerminal::new()?;
    /// let interactive = terminal.stdout_is_terminal();
    /// # Ok::<(), vault_cli::terminal::TerminalError>(())
    /// ```
    fn stdout_is_terminal(&self) -> bool {
        io::stdout().is_terminal()
    }
}
