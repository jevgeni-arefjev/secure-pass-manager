//! Runs the `vault` command line: `init` / `unlock` open the vault shell, `gen` prints
//! a password.
//!
//! Security:
//! - Unlock gets three tries; every failure looks the same (the core enforces a minimum
//!   delay and one message for a wrong vaultname or master password).
//! - Auto-lock is active: a watcher thread wipes the session the moment the idle
//!   timeout passes, even while the shell waits for input, then clears the clipboard.
//!   The process exits on the next input, once the terminal can be restored.
//! - SIGTERM, SIGHUP, SIGINT and SIGQUIT lock the vault and clear the clipboard before
//!   the process exits (Unix).
//! - A panic in the vault shell wipes the session (without an audit event) and clears
//!   the clipboard, then the CLI exits with a failure status (ADR-0014).
//! - Once the vault is locked, by any route, the process ends; it never keeps running
//!   without a session.

use std::ffi::OsString;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use clap::Parser;
use clap::error::{ContextKind, ContextValue, ErrorKind};
use vault_core::audit::{AuditSink, FileSink};
use vault_core::crypto::MasterPassword;
use vault_core::generator;
use vault_core::session::{Clock, Session, SessionConfig, SessionError};
use vault_core::storage::{FileStore, StorageError, VaultStore, Vaultname};

use crate::args::{self, Cli, Command, Open, ShellLine};
use crate::commands::{self, CommandError, Flow, SharedSession};
use crate::terminal::{Terminal, TerminalError, TerminalHandle};

/// How many times unlock or init asks for the master password before giving up.
const MAX_ATTEMPTS: usize = 3;

/// The prompt of the vault shell.
const PROMPT: &str = "vault> ";

/// What the CLI needs from its surroundings; tests swap the clock and the timings.
///
/// ```no_run
/// use std::sync::Arc;
/// use std::time::Duration;
/// use vault_cli::shell::Env;
/// use vault_core::session::SystemClock;
///
/// let env = Env {
///     default_vault_dir: Some("/home/alice/.local/share/secure-pass-manager/vaults".into()),
///     clock: Arc::new(SystemClock),
///     lock_check_interval: Duration::from_secs(1),
///     handle_signals: true,
/// };
/// ```
pub struct Env {
    /// Vault directory used when `--vault-dir` is not given.
    pub default_vault_dir: Option<PathBuf>,
    /// Where the session's time comes from.
    pub clock: Arc<dyn Clock>,
    /// How often the auto-lock watcher checks the idle timeout.
    pub lock_check_interval: Duration,
    /// Whether to lock on termination signals (only the real binary does).
    pub handle_signals: bool,
}

/// How the CLI ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    /// Status 0.
    Success,
    /// Status 1: unlock failed, a storage error, the vault was locked under the shell.
    Failure,
    /// Status 2: the command line didn't parse.
    Usage,
}

impl From<Exit> for ExitCode {
    /// The process exit status for `exit`.
    ///
    /// ```
    /// # use std::process::ExitCode;
    /// # use vault_cli::shell::Exit;
    /// assert_eq!(ExitCode::from(Exit::Usage), ExitCode::from(2));
    /// ```
    fn from(exit: Exit) -> Self {
        match exit {
            Exit::Success => Self::SUCCESS,
            Exit::Failure => Self::FAILURE,
            Exit::Usage => Self::from(2),
        }
    }
}

/// Runs `vault` with `args` (including the program name) on `terminal`.
///
/// ```no_run
/// use vault_cli::shell::{self, Env};
/// use vault_cli::terminal::StdTerminal;
/// # fn env() -> Env { unimplemented!() }
///
/// let mut terminal = StdTerminal::new()?;
/// let exit = shell::run(std::env::args_os(), &mut terminal, &env());
/// # Ok::<(), vault_cli::terminal::TerminalError>(())
/// ```
pub fn run(
    args: impl IntoIterator<Item = OsString>,
    terminal: &mut dyn Terminal,
    env: &Env,
) -> Exit {
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(err) => return usage_error(&err, terminal),
    };
    match cli.command {
        Command::Gen(options) => match generator::generate_password(options.length) {
            Ok(password) => {
                terminal.print(password.reveal());
                Exit::Success
            }
            Err(err) => fail(terminal, err),
        },
        Command::Init(open) => open_vault(terminal, env, cli.vault_dir, &open, Opening::Create),
        Command::Unlock(open) => open_vault(terminal, env, cli.vault_dir, &open, Opening::Unlock),
    }
}

/// Whether a vault is being created or unlocked.
#[derive(Clone, Copy)]
enum Opening {
    /// `vault init`.
    Create,
    /// `vault unlock`.
    Unlock,
}

/// Reports a command line that didn't parse; help and version go to stdout as success.
///
/// ```ignore
/// return usage_error(&err, terminal);
/// ```
fn usage_error(err: &clap::Error, terminal: &mut dyn Terminal) -> Exit {
    if matches!(
        err.kind(),
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
    ) {
        terminal.print(err.render().to_string().trim_end());
        return Exit::Success;
    }
    let unknown = match err.get(ContextKind::InvalidSubcommand) {
        Some(ContextValue::String(name)) => name.as_str(),
        _ => "",
    };
    if args::is_shell_only(unknown) {
        terminal.print_error(&format!(
            "vault: `{unknown}` works inside the vault shell; run `vault unlock` first"
        ));
    } else {
        terminal.print_error(err.render().to_string().trim_end());
    }
    Exit::Usage
}

/// Reports `err` ([`commands::report`]) and returns [`Exit::Failure`].
///
/// ```ignore
/// return fail(terminal, SessionError::InvalidVaultname);
/// ```
fn fail(terminal: &mut dyn Terminal, err: impl Into<CommandError>) -> Exit {
    commands::report(terminal, &err.into());
    Exit::Failure
}

/// `init` / `unlock`: opens the vault directory, asks for the vaultname if needed,
/// creates or unlocks the vault, and runs the vault shell on it.
///
/// ```ignore
/// open_vault(terminal, env, cli.vault_dir, &open, Opening::Unlock)
/// ```
fn open_vault(
    terminal: &mut dyn Terminal,
    env: &Env,
    vault_dir: Option<PathBuf>,
    open: &Open,
    opening: Opening,
) -> Exit {
    let Some(dir) = vault_dir.or_else(|| env.default_vault_dir.clone()) else {
        terminal.print_error("vault: no data directory found; pass --vault-dir <PATH>");
        return Exit::Failure;
    };
    let store = match FileStore::new(&dir) {
        Ok(store) => store,
        Err(err) => return fail(terminal, err),
    };
    let audit: Arc<dyn AuditSink> = Arc::new(FileSink::new(dir.clone()));
    // Installed before the first prompt, so a signal during a master password prompt
    // (terminal in raw mode) still restores the terminal; the session joins it once
    // the vault is open.
    let shared: SharedSession = Arc::new(Mutex::new(None));
    #[cfg(unix)]
    if env.handle_signals {
        signals::lock_on_termination(Arc::clone(&shared), terminal.handle());
    }
    // Surrounding spaces are trimmed by `Vaultname::parse`, as on the web.
    let vaultname = match &open.vaultname {
        Some(name) => name.clone(),
        None => match terminal.read_line("Vaultname: ") {
            Ok(name) => String::from(name.as_str()),
            Err(err) => return fail(terminal, err),
        },
    };
    let Ok(name) = Vaultname::parse(&vaultname) else {
        return fail(terminal, SessionError::InvalidVaultname);
    };
    let idle_timeout = Duration::from_secs(open.idle_timeout * 60);
    let config = || SessionConfig {
        idle_timeout,
        clock: Arc::clone(&env.clock),
        audit: Arc::clone(&audit),
    };
    let session = match opening {
        Opening::Create => create(terminal, &store, &name, &config),
        Opening::Unlock => unlock(terminal, &store, &vaultname, &config),
    };
    match session {
        Ok(session) => vault_shell(terminal, env, shared, session, &dir, open.idle_timeout),
        Err(exit) => exit,
    }
}

/// Creates a new vault, asking for its master password up to [`MAX_ATTEMPTS`] times
/// (too weak, caught before the repeat prompt, or mismatched). Refuses at once if the
/// vaultname is taken.
///
/// ```ignore
/// let session = create(terminal, &store, &name, &config)?;
/// ```
fn create(
    terminal: &mut dyn Terminal,
    store: &FileStore,
    name: &Vaultname,
    config: &dyn Fn() -> SessionConfig,
) -> Result<Session<FileStore>, Exit> {
    // A cheap check before any prompt; `Session::create` still refuses atomically.
    match store.load(name) {
        Err(StorageError::NotFound) => {}
        Ok(_) | Err(StorageError::NotAVault) => {
            return Err(fail(terminal, SessionError::VaultExists));
        }
        Err(err) => return Err(fail(terminal, err)),
    }
    for _ in 0..MAX_ATTEMPTS {
        let password = match commands::new_master_password(terminal, "New master password: ") {
            Ok(password) => password,
            Err(
                err @ (CommandError::PasswordsDiffer
                | CommandError::Session(SessionError::WeakMasterPassword(_))),
            ) => {
                terminal.print_error(&format!("vault: {err}"));
                continue;
            }
            Err(err) => return Err(fail(terminal, err)),
        };
        return Session::create(store.clone(), &name.to_string(), &password, config())
            .map_err(|err| fail(terminal, err));
    }
    Err(Exit::Failure)
}

/// Unlocks a vault, asking for the master password up to [`MAX_ATTEMPTS`] times.
///
/// ```ignore
/// let session = unlock(terminal, &store, "alice", &config)?;
/// ```
fn unlock(
    terminal: &mut dyn Terminal,
    store: &FileStore,
    vaultname: &str,
    config: &dyn Fn() -> SessionConfig,
) -> Result<Session<FileStore>, Exit> {
    for _ in 0..MAX_ATTEMPTS {
        let mut typed = match terminal.read_hidden("Master password: ") {
            Ok(typed) => typed,
            Err(err) => return Err(fail(terminal, err)),
        };
        let password = MasterPassword::new(std::mem::take(&mut *typed));
        match Session::unlock(store.clone(), vaultname, &password, config()) {
            Ok(session) => return Ok(session),
            Err(SessionError::UnlockFailed) => {
                terminal.print_error(&format!("vault: {}", SessionError::UnlockFailed));
            }
            Err(err) => return Err(fail(terminal, err)),
        }
    }
    Err(Exit::Failure)
}

/// The vault shell: reads and runs commands until `lock`, Ctrl-D, auto-lock, a lost
/// session or a panic, then locks the vault and clears the clipboard. `slot` is the
/// (empty) shared slot the signal handler already watches; the session is put in it.
///
/// ```ignore
/// vault_shell(terminal, env, shared, session, &vault_dir, 5)
/// ```
fn vault_shell(
    terminal: &mut dyn Terminal,
    env: &Env,
    slot: SharedSession,
    session: Session<FileStore>,
    vault_dir: &Path,
    idle_minutes: u64,
) -> Exit {
    terminal.print(&format!(
        "vault '{}' unlocked; it locks after {idle_minutes} idle minute(s). Type `help` for commands.",
        session.vaultname()
    ));
    *slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(session);
    let session = slot;
    let handle = terminal.handle();
    let auto_locked = Arc::new(AtomicBool::new(false));
    let (stop_watcher, watcher) = spawn_auto_lock(
        Arc::clone(&session),
        Arc::clone(&handle),
        Arc::clone(&auto_locked),
        env.lock_check_interval,
    );

    // A panic (its location already printed by the hook) still wipes the session and
    // clears the clipboard below, without an audit event (ADR-0014).
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        run_commands(terminal, &session, vault_dir, &auto_locked)
    }));

    drop(stop_watcher);
    let _ = watcher.join();
    let open = session
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    let panicked = outcome.is_err();
    let exit = match outcome {
        Ok(exit) => {
            if let Some(open) = open {
                open.lock();
            }
            exit
        }
        // Dropping the session zeroizes its keys and secrets; nothing is audited.
        Err(_) => {
            drop(open);
            Exit::Failure
        }
    };
    handle.clear_clipboard();
    if exit == Exit::Success || panicked {
        terminal.print("vault locked");
    }
    exit
}

/// Reads and runs vault shell commands until `lock`, Ctrl-D, auto-lock or a lost
/// session; the caller then locks the vault.
///
/// ```ignore
/// let exit = run_commands(terminal, &session, vault_dir, &auto_locked);
/// ```
fn run_commands(
    terminal: &mut dyn Terminal,
    session: &SharedSession,
    vault_dir: &Path,
    auto_locked: &AtomicBool,
) -> Exit {
    loop {
        let line = terminal.read_command(PROMPT);
        if auto_locked.load(Ordering::SeqCst) {
            return Exit::Failure;
        }
        let line = match line {
            Ok(line) => line,
            Err(TerminalError::Interrupted) => continue,
            Err(TerminalError::EndOfInput) => return Exit::Success,
            Err(err) => return fail(terminal, err),
        };
        let Some(words) = shlex::split(&line).map(zeroize::Zeroizing::new) else {
            terminal.print_error("vault: unbalanced quotes");
            continue;
        };
        if words.is_empty() {
            continue;
        }
        let command = match ShellLine::try_parse_from(words.iter()) {
            Ok(line) => line.command,
            Err(err) if err.kind() == ErrorKind::DisplayHelp => {
                terminal.print(err.render().to_string().trim_end());
                continue;
            }
            Err(err) => {
                terminal.print_error(&shell_usage_error(&err));
                continue;
            }
        };
        match commands::execute(command, terminal, session, vault_dir) {
            Ok(Flow::Continue) => {}
            Ok(Flow::Lock) => return Exit::Success,
            Err(err) => {
                commands::report(terminal, &err);
                if err.ends_session() {
                    return Exit::Failure;
                }
            }
        }
    }
}

/// The message for a vault shell line that didn't parse.
///
/// Security: an unknown command or an unexpected argument is reported without the
/// word itself, since a person who pastes a password at `vault>` by mistake would
/// otherwise see it echoed (and kept in the scrollback). Only clap's suggestions, which
/// are known command and flag names, are shown. Other errors (a missing title, a bad
/// `--limit`) keep clap's message; they quote only flags and their values.
///
/// ```ignore
/// terminal.print_error(&shell_usage_error(&err));
/// ```
fn shell_usage_error(err: &clap::Error) -> String {
    let (what, suggestion) = match err.kind() {
        ErrorKind::InvalidSubcommand => ("unknown command", ContextKind::SuggestedSubcommand),
        ErrorKind::UnknownArgument => ("unexpected argument", ContextKind::SuggestedArg),
        _ => return err.render().to_string().trim_end().to_owned(),
    };
    let suggested = match err.get(suggestion) {
        Some(ContextValue::String(name)) => Some(name.as_str()),
        Some(ContextValue::Strings(names)) => names.first().map(String::as_str),
        _ => None,
    };
    match suggested {
        Some(name) => format!("vault: {what} (did you mean `{name}`?); type `help` for commands"),
        None => format!("vault: {what}; type `help` for commands"),
    }
}

/// Starts the auto-lock watcher: every `interval` it checks the idle timeout, and once
/// it has passed, wipes the session, clears the clipboard, sets `auto_locked` and says
/// so above the prompt. Dropping the returned sender stops it.
///
/// Security: a panic during the check (its location printed by the hook) wipes the
/// session the same way, without an audit event, so auto-lock never silently stops
/// while the vault stays unlocked.
///
/// ```ignore
/// let (stop, watcher) = spawn_auto_lock(session, handle, auto_locked, Duration::from_secs(1));
/// drop(stop);
/// watcher.join();
/// ```
fn spawn_auto_lock(
    session: SharedSession,
    handle: Arc<dyn TerminalHandle>,
    auto_locked: Arc<AtomicBool>,
    interval: Duration,
) -> (mpsc::Sender<()>, JoinHandle<()>) {
    let (stop, stopped) = mpsc::channel::<()>();
    let watcher = thread::spawn(move || {
        while let Err(RecvTimeoutError::Timeout) = stopped.recv_timeout(interval) {
            let notice = match panic::catch_unwind(AssertUnwindSafe(|| lock_if_idle(&session))) {
                Ok(Watch::Open) => continue,
                Ok(Watch::Gone) => return,
                Ok(Watch::Locked) => "vault locked (idle); press Enter to close",
                // Dropping the session zeroizes its keys and secrets; nothing is audited.
                Err(_) => {
                    drop(
                        session
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .take(),
                    );
                    "vault locked (internal error); press Enter to close"
                }
            };
            handle.clear_clipboard();
            auto_locked.store(true, Ordering::SeqCst);
            handle.notify(notice);
            return;
        }
    });
    (stop, watcher)
}

/// What one auto-lock check found.
enum Watch {
    /// The session is still unlocked.
    Open,
    /// The shell already took the session; the watcher has nothing left to do.
    Gone,
    /// The idle timeout had passed; the session is now locked.
    Locked,
}

/// Locks the session if its idle timeout has passed.
///
/// ```ignore
/// if let Watch::Locked = lock_if_idle(&session) { handle.clear_clipboard(); }
/// ```
fn lock_if_idle(session: &SharedSession) -> Watch {
    let mut guard = session.lock().unwrap_or_else(PoisonError::into_inner);
    let idle = match guard.as_mut() {
        Some(open) => !open.is_unlocked(),
        None => return Watch::Gone,
    };
    if !idle {
        return Watch::Open;
    }
    if let Some(open) = guard.take() {
        open.lock();
    }
    Watch::Locked
}

/// Termination signals (Unix only).
#[cfg(unix)]
mod signals {
    use std::sync::{Arc, PoisonError};
    use std::thread;

    use signal_hook::consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
    use signal_hook::iterator::Signals;

    use crate::commands::SharedSession;
    use crate::terminal::TerminalHandle;

    /// On SIGTERM, SIGHUP, SIGINT or SIGQUIT: wipes the session if one is open
    /// (recording it in the audit log), clears the clipboard, restores the terminal if
    /// our masked prompt had it in raw mode with bracketed paste, and exits with
    /// 128 + the signal number. Installed before the first master password prompt,
    /// while `session` is still empty. If the handler can't be installed, the default
    /// action (exit without wiping) stays, and a warning is logged.
    ///
    /// ```ignore
    /// signals::lock_on_termination(Arc::clone(&session), terminal.handle());
    /// ```
    pub(super) fn lock_on_termination(session: SharedSession, handle: Arc<dyn TerminalHandle>) {
        let mut signals = match Signals::new([SIGTERM, SIGHUP, SIGINT, SIGQUIT]) {
            Ok(signals) => signals,
            Err(_) => {
                tracing::warn!(event = "signal_handlers_unavailable");
                return;
            }
        };
        thread::spawn(move || {
            if let Some(signal) = signals.forever().next() {
                if let Some(open) = session
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take()
                {
                    open.lock_on_signal();
                }
                handle.clear_clipboard();
                // Only the masked prompt enables crossterm's raw mode; undo both of
                // its switches, as its drop guard would.
                if crossterm::terminal::is_raw_mode_enabled().unwrap_or(false) {
                    let _ = crossterm::execute!(
                        std::io::stderr(),
                        crossterm::event::DisableBracketedPaste
                    );
                    let _ = crossterm::terminal::disable_raw_mode();
                }
                std::process::exit(128 + signal);
            }
        });
    }
}
