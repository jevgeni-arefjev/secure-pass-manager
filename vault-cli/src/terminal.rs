//! Everything the CLI reads from or writes to the person, behind one [`Terminal`] trait,
//! so the vault shell can be driven by a scripted fake in tests.
//!
//! [`StdTerminal`] is the real one: `rustyline` for visible lines (command history kept
//! in memory only, never written to a file) and our own masked prompt for hidden input
//! (ADR-0008). It also owns the clipboard ([`crate::clipboard`]).

mod masked;

use std::fmt;
use std::io::{self, IsTerminal, Write};
use std::sync::{Arc, Mutex, PoisonError};

use rustyline::config::Config;
use rustyline::error::ReadlineError;
use rustyline::{DefaultEditor, ExternalPrinter};
use vault_core::session::HiddenValue;
use zeroize::Zeroizing;

use crate::clipboard::Clipboard;

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
    /// There is no clipboard to copy to (e.g. no display).
    NoClipboard,
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
            Self::NoClipboard => "the clipboard is not available",
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

    /// Copies `value` to the clipboard, to be cleared again after a while.
    fn copy_to_clipboard(&mut self, value: &HiddenValue) -> Result<(), TerminalError>;

    /// The parts of the terminal other threads (auto-lock, signals) may use.
    fn handle(&mut self) -> Arc<dyn TerminalHandle>;
}

/// What a background thread may do to the terminal while the shell waits for input.
///
/// ```ignore
/// let handle = terminal.handle();
/// std::thread::spawn(move || {
///     handle.clear_clipboard();
///     handle.notify("vault locked (idle)");
/// });
/// ```
pub trait TerminalHandle: Send + Sync {
    /// Shows `message` above the prompt that is waiting for input.
    fn notify(&self, message: &str);

    /// Clears the clipboard if it still holds a value we copied.
    fn clear_clipboard(&self);
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
    clipboard: Clipboard,
    handle: Option<Arc<StdHandle>>,
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
            clipboard: Clipboard::new(),
            handle: None,
        })
    }
}

impl Drop for StdTerminal {
    /// Clears our copy from the clipboard when the CLI exits.
    ///
    /// ```no_run
    /// # let terminal = vault_cli::terminal::StdTerminal::new()?;
    /// drop(terminal);
    /// # Ok::<(), vault_cli::terminal::TerminalError>(())
    /// ```
    fn drop(&mut self) {
        self.clipboard.clear_if_ours();
    }
}

/// [`TerminalHandle`] for [`StdTerminal`]: prints through rustyline's external printer
/// (so the message appears above a waiting prompt), or to stderr if there is none.
struct StdHandle {
    printer: Mutex<Option<Box<dyn ExternalPrinter + Send>>>,
    clipboard: Clipboard,
}

impl TerminalHandle for StdHandle {
    /// Prints `message` above the prompt, falling back to stderr.
    ///
    /// ```ignore
    /// handle.notify("vault locked (idle)");
    /// ```
    fn notify(&self, message: &str) {
        let mut printer = self.printer.lock().unwrap_or_else(PoisonError::into_inner);
        let printed = printer
            .as_mut()
            .is_some_and(|p| p.print(format!("{message}\n")).is_ok());
        if !printed {
            let _ = writeln!(io::stderr(), "{message}");
        }
    }

    /// Clears our copy from the clipboard.
    ///
    /// ```ignore
    /// handle.clear_clipboard();
    /// ```
    fn clear_clipboard(&self) {
        self.clipboard.clear_if_ours();
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

    /// Copies through the system clipboard, cleared after [`crate::clipboard::CLEAR_AFTER`].
    ///
    /// ```no_run
    /// # use vault_cli::terminal::{StdTerminal, Terminal};
    /// # use vault_core::session::HiddenValue;
    /// # let mut terminal = StdTerminal::new()?;
    /// terminal.copy_to_clipboard(&HiddenValue::new("s3cret!".into()))?;
    /// # Ok::<(), vault_cli::terminal::TerminalError>(())
    /// ```
    fn copy_to_clipboard(&mut self, value: &HiddenValue) -> Result<(), TerminalError> {
        self.clipboard
            .copy(value)
            .map_err(|_| TerminalError::NoClipboard)
    }

    /// One shared handle, created on first use.
    ///
    /// ```no_run
    /// # use vault_cli::terminal::{StdTerminal, Terminal};
    /// # let mut terminal = StdTerminal::new()?;
    /// let handle = terminal.handle();
    /// handle.notify("hello from another thread");
    /// # Ok::<(), vault_cli::terminal::TerminalError>(())
    /// ```
    fn handle(&mut self) -> Arc<dyn TerminalHandle> {
        if self.handle.is_none() {
            let printer = self.editor.create_external_printer().ok();
            self.handle = Some(Arc::new(StdHandle {
                printer: Mutex::new(
                    printer.map(|p| Box::new(p) as Box<dyn ExternalPrinter + Send>),
                ),
                clipboard: self.clipboard.clone(),
            }));
        }
        self.handle.clone().expect("created above")
    }
}
