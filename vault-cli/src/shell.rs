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
//! - Once the vault is locked, by any route, the process ends; it never keeps running
//!   without a session.

use std::ffi::OsString;
use std::path::PathBuf;
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
            Err(err) => fail(terminal, &err),
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

/// Prints `vault: <err>` to stderr and returns [`Exit::Failure`].
///
/// ```ignore
/// return fail(terminal, &SessionError::InvalidVaultname);
/// ```
fn fail(terminal: &mut dyn Terminal, err: &dyn std::fmt::Display) -> Exit {
    terminal.print_error(&format!("vault: {err}"));
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
        return fail(
            terminal,
            &"no data directory found; pass --vault-dir <PATH>",
        );
    };
    let store = match FileStore::new(&dir) {
        Ok(store) => store,
        Err(err) => return fail(terminal, &err),
    };
    let audit: Arc<dyn AuditSink> = Arc::new(FileSink::new(dir));
    let vaultname = match &open.vaultname {
        Some(name) => name.trim().to_owned(),
        None => match terminal.read_line("Vaultname: ") {
            Ok(name) => name.trim().to_owned(),
            Err(err) => return fail(terminal, &err),
        },
    };
    let Ok(name) = Vaultname::parse(&vaultname) else {
        return fail(terminal, &SessionError::InvalidVaultname);
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
        Ok(session) => vault_shell(terminal, env, session, open.idle_timeout),
        Err(exit) => exit,
    }
}

/// Creates a new vault, asking for its master password up to [`MAX_ATTEMPTS`] times
/// (mismatched or too weak). Refuses at once if the vaultname is taken.
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
            return Err(fail(terminal, &SessionError::VaultExists));
        }
        Err(err) => return Err(fail(terminal, &err)),
    }
    for _ in 0..MAX_ATTEMPTS {
        let password = match commands::new_master_password(terminal, "New master password: ") {
            Ok(password) => password,
            Err(CommandError::PasswordsDiffer) => {
                terminal.print_error(&format!("vault: {}", CommandError::PasswordsDiffer));
                continue;
            }
            Err(err) => return Err(fail(terminal, &err)),
        };
        match Session::create(store.clone(), &name.to_string(), &password, config()) {
            Ok(session) => return Ok(session),
            Err(SessionError::WeakMasterPassword(weak)) => {
                terminal.print_error(&format!("vault: {weak}"));
            }
            Err(err) => return Err(fail(terminal, &err)),
        }
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
            Err(err) => return Err(fail(terminal, &err)),
        };
        let password = MasterPassword::new(std::mem::take(&mut *typed));
        match Session::unlock(store.clone(), vaultname, &password, config()) {
            Ok(session) => return Ok(session),
            Err(SessionError::UnlockFailed) => {
                terminal.print_error(&format!("vault: {}", SessionError::UnlockFailed));
            }
            Err(err) => return Err(fail(terminal, &err)),
        }
    }
    Err(Exit::Failure)
}

/// The vault shell: reads and runs commands until `lock`, Ctrl-D, auto-lock or a lost
/// session, then locks the vault and clears the clipboard.
///
/// ```ignore
/// vault_shell(terminal, env, session, 5)
/// ```
fn vault_shell(
    terminal: &mut dyn Terminal,
    env: &Env,
    session: Session<FileStore>,
    idle_minutes: u64,
) -> Exit {
    terminal.print(&format!(
        "vault '{}' unlocked; it locks after {idle_minutes} idle minute(s). Type `help` for commands.",
        session.vaultname()
    ));
    let session: SharedSession = Arc::new(Mutex::new(Some(session)));
    let handle = terminal.handle();
    let auto_locked = Arc::new(AtomicBool::new(false));
    let (stop_watcher, watcher) = spawn_auto_lock(
        Arc::clone(&session),
        Arc::clone(&handle),
        Arc::clone(&auto_locked),
        env.lock_check_interval,
    );
    #[cfg(unix)]
    if env.handle_signals {
        signals::lock_on_termination(Arc::clone(&session), Arc::clone(&handle));
    }

    let exit = loop {
        let line = terminal.read_command(PROMPT);
        if auto_locked.load(Ordering::SeqCst) {
            break Exit::Failure;
        }
        let line = match line {
            Ok(line) => line,
            Err(TerminalError::Interrupted) => continue,
            Err(TerminalError::EndOfInput) => break Exit::Success,
            Err(err) => break fail(terminal, &err),
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
                terminal.print_error(err.render().to_string().trim_end());
                continue;
            }
        };
        match commands::execute(command, terminal, &session) {
            Ok(Flow::Continue) => {}
            Ok(Flow::Lock) => break Exit::Success,
            Err(err) => {
                terminal.print_error(&format!("vault: {err}"));
                if err.ends_session() {
                    break Exit::Failure;
                }
            }
        }
    };

    drop(stop_watcher);
    let _ = watcher.join();
    if let Some(session) = session
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
    {
        session.lock();
    }
    handle.clear_clipboard();
    if exit == Exit::Success {
        terminal.print("vault locked");
    }
    exit
}

/// Starts the auto-lock watcher: every `interval` it checks the idle timeout, and once
/// it has passed, wipes the session, clears the clipboard, sets `auto_locked` and says
/// so above the prompt. Dropping the returned sender stops it.
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
            let mut guard = session.lock().unwrap_or_else(PoisonError::into_inner);
            let idle = match guard.as_mut() {
                Some(open) => !open.is_unlocked(),
                None => return,
            };
            if idle {
                if let Some(session) = guard.take() {
                    session.lock();
                }
                drop(guard);
                handle.clear_clipboard();
                auto_locked.store(true, Ordering::SeqCst);
                handle.notify("vault locked (idle); press Enter to close");
                return;
            }
        }
    });
    (stop, watcher)
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

    /// On SIGTERM, SIGHUP, SIGINT or SIGQUIT: wipes the session (recording it in the
    /// audit log), clears the clipboard,
    /// restores the terminal if our masked prompt had it in raw mode, and exits with
    /// 128 + the signal number. If the handler can't be installed, the default action
    /// (exit without wiping) stays, and a warning is logged.
    ///
    /// ```ignore
    /// signals::lock_on_termination(Arc::clone(&session), Arc::clone(&handle));
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
                let _ = crossterm::terminal::disable_raw_mode();
                std::process::exit(128 + signal);
            }
        });
    }
}
