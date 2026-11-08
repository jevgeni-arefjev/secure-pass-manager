//! Shared helpers for the `vault` CLI tests: a scripted fake terminal, a manual clock
//! and a temporary vault directory to run `shell::run` on.
//!
//! The fake panics if a hidden value is read through a visible prompt (or the other
//! way round), so every test also checks that secrets only go through hidden prompts.
//! Vaults are pre-created in the test format (cheap KDF); only `init` pays for the
//! production Argon2id parameters.
#![allow(dead_code)] // each test binary uses a different subset

use std::collections::VecDeque;
use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tempfile::TempDir;
use vault_cli::shell::{self, Env, Exit};
use vault_cli::terminal::{Terminal, TerminalError, TerminalHandle};
use vault_core::audit::FileSink;
use vault_core::crypto::MasterPassword;
use vault_core::session::{Clock, HiddenValue, Session, SessionConfig};
use vault_core::storage::FileStore;
use zeroize::Zeroizing;

/// The master password of the `alice` vault made by [`Fixture::with_alice`].
pub const PASSWORD: &str = "correct horse battery";

/// A clock that only moves when told to (sleeping moves it too), and panics once
/// `panicking` is set.
pub struct ManualClock {
    /// When the clock started.
    start: Instant,
    /// How far it has been moved since.
    elapsed: Mutex<Duration>,
    /// Set to make every later reading panic.
    panicking: AtomicBool,
}

impl ManualClock {
    /// Moves the clock forward by `by`.
    ///
    /// ```text
    /// clock.advance(Duration::from_secs(60));
    /// ```
    pub fn advance(&self, by: Duration) {
        *self.elapsed.lock().unwrap() += by;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Instant {
        assert!(
            !self.panicking.load(Ordering::SeqCst),
            "scripted clock panic"
        );
        self.start + *self.elapsed.lock().unwrap()
    }

    fn unix_time(&self) -> u64 {
        1_800_000_000 + self.elapsed.lock().unwrap().as_secs()
    }

    fn sleep(&self, duration: Duration) {
        self.advance(duration);
    }
}

/// One scripted answer from the person.
pub enum Input {
    /// A visible line (command, field value, vaultname, yes/no).
    Line(String),
    /// A hidden line (master password, hidden field).
    Hidden(String),
    /// Ctrl-C.
    Interrupt,
    /// A hidden prompt that the real terminal ended with this error (e.g. a refused paste).
    HiddenRefused(TerminalError),
    /// Leave the shell idle for this long, then wait until it reports the auto-lock.
    Idle(Duration),
    /// The terminal panics, standing in for a bug anywhere in the vault shell.
    Panic,
    /// The clock starts panicking; wait until the auto-lock watcher reports it.
    ClockPanics,
}

/// What background threads saw: notices above the prompt and the clipboard.
#[derive(Default)]
pub struct Shared {
    /// Messages shown above the prompt, in order.
    pub notices: Mutex<Vec<String>>,
    /// What is on the fake clipboard.
    pub clipboard: Mutex<Option<String>>,
}

impl TerminalHandle for Shared {
    fn notify(&self, message: &str) {
        self.notices.lock().unwrap().push(message.to_owned());
    }

    fn clear_clipboard(&self) {
        *self.clipboard.lock().unwrap() = None;
    }
}

/// A visible line in a script.
///
/// ```text
/// vec![line("list")]
/// ```
pub fn line(text: &str) -> Input {
    Input::Line(text.to_owned())
}

/// A hidden line in a script.
///
/// ```text
/// vec![hidden(PASSWORD)]
/// ```
pub fn hidden(text: &str) -> Input {
    Input::Hidden(text.to_owned())
}

/// A scripted terminal that records everything printed.
///
/// Security: panics when a scripted hidden value meets a visible prompt or the other
/// way round, so a test fails if a secret is ever read through a visible prompt.
/// `copied` keeps the last copied value in plain text for tests to check.
pub struct FakeTerminal {
    /// The answers still to give, in order.
    inputs: VecDeque<Input>,
    /// The clock that idle periods move.
    clock: Arc<ManualClock>,
    /// What background threads saw.
    pub shared: Arc<Shared>,
    /// What [`Terminal::stdout_is_terminal`] answers.
    stdout_is_terminal: bool,
    /// Everything printed to stdout, one entry per `print`.
    pub out: Vec<String>,
    /// Everything printed to stderr, one entry per `print_error`.
    pub err: Vec<String>,
    /// The prompt of every hidden read, in order.
    pub hidden_prompts: Vec<String>,
    /// The last value copied, kept after the clipboard is cleared.
    pub copied: Option<String>,
}

impl FakeTerminal {
    /// The next scripted input, after acting out any idle periods; `None` when the
    /// script has run out (behaves like Ctrl-D).
    ///
    /// ```text
    /// let input = self.next();
    /// ```
    fn next(&mut self) -> Option<Input> {
        loop {
            match self.inputs.pop_front()? {
                Input::Idle(duration) => {
                    self.clock.advance(duration);
                    self.wait_for_notice();
                }
                Input::ClockPanics => {
                    self.clock.panicking.store(true, Ordering::SeqCst);
                    self.wait_for_notice();
                }
                input => return Some(input),
            }
        }
    }

    /// Waits until the auto-lock watcher has said something above the prompt.
    ///
    /// ```text
    /// self.wait_for_notice();
    /// ```
    fn wait_for_notice(&self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.shared.notices.lock().unwrap().is_empty() {
            assert!(Instant::now() < deadline, "auto-lock never fired");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Reads a visible line; panics if the script has a hidden value here.
    ///
    /// ```text
    /// self.visible(prompt)
    /// ```
    fn visible(&mut self, prompt: &str) -> Result<Zeroizing<String>, TerminalError> {
        match self.next() {
            Some(Input::Line(line)) => Ok(Zeroizing::new(line)),
            Some(Input::Hidden(_) | Input::HiddenRefused(_)) => {
                panic!("hidden input read through visible prompt {prompt:?}")
            }
            Some(Input::Interrupt) => Err(TerminalError::Interrupted),
            Some(Input::Idle(_)) => unreachable!("handled in next"),
            Some(Input::Panic) => panic!("scripted panic"),
            Some(Input::ClockPanics) => unreachable!("handled in next"),
            None => Err(TerminalError::EndOfInput),
        }
    }

    /// Everything printed to stdout, one entry per `print`.
    ///
    /// ```text
    /// assert!(terminal.stdout().contains("secret added"));
    /// ```
    pub fn stdout(&self) -> String {
        self.out.join("\n")
    }

    /// Everything printed to stderr.
    ///
    /// ```text
    /// assert!(terminal.stderr().contains("wrong vaultname"));
    /// ```
    pub fn stderr(&self) -> String {
        self.err.join("\n")
    }

    /// Everything shown above the prompt by background threads.
    ///
    /// ```text
    /// assert!(terminal.notices().contains("vault locked"));
    /// ```
    pub fn notices(&self) -> String {
        self.shared.notices.lock().unwrap().join("\n")
    }

    /// What is on the fake clipboard.
    ///
    /// ```text
    /// assert_eq!(terminal.clipboard(), None);
    /// ```
    pub fn clipboard(&self) -> Option<String> {
        self.shared.clipboard.lock().unwrap().clone()
    }
}

impl Terminal for FakeTerminal {
    fn read_command(&mut self, prompt: &str) -> Result<Zeroizing<String>, TerminalError> {
        self.visible(prompt)
    }

    fn read_line(&mut self, prompt: &str) -> Result<Zeroizing<String>, TerminalError> {
        self.visible(prompt)
    }

    fn read_hidden(&mut self, prompt: &str) -> Result<Zeroizing<String>, TerminalError> {
        self.hidden_prompts.push(prompt.to_owned());
        match self.next() {
            Some(Input::Hidden(value)) => Ok(Zeroizing::new(value)),
            Some(Input::HiddenRefused(err)) => Err(err),
            Some(Input::Line(line)) => panic!("visible line {line:?} read through hidden prompt"),
            Some(Input::Interrupt) => Err(TerminalError::Interrupted),
            Some(Input::Idle(_)) => unreachable!("handled in next"),
            Some(Input::Panic) => panic!("scripted panic"),
            Some(Input::ClockPanics) => unreachable!("handled in next"),
            None => Err(TerminalError::EndOfInput),
        }
    }

    fn print(&mut self, text: &str) {
        self.out.push(text.to_owned());
    }

    fn print_error(&mut self, text: &str) {
        self.err.push(text.to_owned());
    }

    fn stdout_is_terminal(&self) -> bool {
        self.stdout_is_terminal
    }

    fn copy_to_clipboard(&mut self, value: &HiddenValue) -> Result<(), TerminalError> {
        self.copied = Some(value.reveal().to_owned());
        *self.shared.clipboard.lock().unwrap() = Some(value.reveal().to_owned());
        Ok(())
    }

    fn handle(&mut self) -> Arc<dyn TerminalHandle> {
        self.shared.clone()
    }
}

/// A temporary vault directory, a manual clock, and helpers to run the CLI on them.
pub struct Fixture {
    /// The vault directory.
    pub dir: TempDir,
    /// The clock every run of the CLI uses.
    clock: Arc<ManualClock>,
}

impl Fixture {
    /// An empty vault directory.
    ///
    /// ```text
    /// let fx = Fixture::new();
    /// ```
    pub fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            clock: Arc::new(ManualClock {
                start: Instant::now(),
                elapsed: Mutex::new(Duration::ZERO),
                panicking: AtomicBool::new(false),
            }),
        }
    }

    /// A fixture with vault `alice` (master password [`PASSWORD`]) already created.
    ///
    /// ```text
    /// let fx = Fixture::with_alice();
    /// ```
    pub fn with_alice() -> Self {
        Self::with_vault("alice", PASSWORD)
    }

    /// A fixture with vault `vaultname` (master password `password`) already created,
    /// in the test format.
    ///
    /// ```text
    /// let fx = Fixture::with_vault("alice", "Unl0ck-Master-Qz7#Lp");
    /// ```
    pub fn with_vault(vaultname: &str, password: &str) -> Self {
        let fx = Self::new();
        let store = FileStore::new(fx.dir.path()).unwrap();
        let password = MasterPassword::new(password.to_owned());
        let config = SessionConfig::new(Arc::new(FileSink::new(fx.dir.path())));
        Session::create_insecure_for_tests(store, vaultname, &password, config)
            .unwrap()
            .lock();
        fx
    }

    /// Runs `vault --vault-dir <dir> <args>` with `inputs` as the person's answers.
    ///
    /// ```text
    /// let (exit, terminal) = fx.run(&["unlock", "alice"], vec![hidden(PASSWORD)]);
    /// ```
    pub fn run(&self, args: &[&str], inputs: Vec<Input>) -> (Exit, FakeTerminal) {
        self.run_on(args, inputs, true)
    }

    /// Like [`Fixture::run`], but saying whether stdout is a terminal.
    ///
    /// ```text
    /// let (exit, terminal) = fx.run_on(&["unlock", "alice"], inputs, false);
    /// ```
    pub fn run_on(
        &self,
        args: &[&str],
        inputs: Vec<Input>,
        stdout_is_terminal: bool,
    ) -> (Exit, FakeTerminal) {
        let mut terminal = FakeTerminal {
            inputs: inputs.into(),
            clock: Arc::clone(&self.clock),
            shared: Arc::default(),
            stdout_is_terminal,
            out: Vec::new(),
            err: Vec::new(),
            hidden_prompts: Vec::new(),
            copied: None,
        };
        let env = Env {
            default_vault_dir: None,
            clock: self.clock.clone(),
            lock_check_interval: Duration::from_millis(5),
            handle_signals: false,
        };
        let mut argv: Vec<OsString> = vec!["vault".into(), "--vault-dir".into()];
        argv.push(self.dir.path().into());
        argv.extend(args.iter().map(OsString::from));
        let exit = shell::run(argv, &mut terminal, &env);
        (exit, terminal)
    }

    /// Unlocks `alice` with [`PASSWORD`] and runs `script` in the vault shell: the
    /// commands, each followed by the answers to its prompts.
    ///
    /// ```text
    /// let (exit, t) = fx.shell(vec![line("list")]);
    /// ```
    pub fn shell(&self, script: Vec<Input>) -> (Exit, FakeTerminal) {
        let mut inputs = vec![hidden(PASSWORD)];
        inputs.extend(script);
        self.run(&["unlock", "alice"], inputs)
    }
}
