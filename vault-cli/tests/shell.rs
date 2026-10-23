//! Behaviour of the `vault` CLI and its vault shell, driven through `shell::run` with a
//! scripted fake terminal and a manual clock.
//!
//! The fake panics if a hidden value is read through a visible prompt (or the other
//! way round), so every test also checks that secrets only go through hidden prompts.
//! Vaults are pre-created in the test format (cheap KDF); only the `init` tests pay for
//! the production Argon2id parameters.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tempfile::TempDir;
use vault_cli::shell::{self, Env, Exit};
use vault_cli::terminal::{Terminal, TerminalError, TerminalHandle};
use vault_core::crypto::MasterPassword;
use vault_core::session::{Clock, HiddenValue, Session, SessionConfig};
use vault_core::storage::SqliteStore;
use zeroize::Zeroizing;

const PASSWORD: &str = "correct horse battery";

/// A clock that only moves when told to (sleeping moves it too).
struct ManualClock {
    start: Instant,
    elapsed: Mutex<Duration>,
}

impl ManualClock {
    /// Moves the clock forward by `by`.
    ///
    /// ```text
    /// clock.advance(Duration::from_secs(60));
    /// ```
    fn advance(&self, by: Duration) {
        *self.elapsed.lock().unwrap() += by;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Instant {
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
enum Input {
    /// A visible line (command, field value, vaultname, yes/no).
    Line(String),
    /// A hidden line (master password, hidden field).
    Hidden(String),
    /// Ctrl-C.
    Interrupt,
    /// Leave the shell idle for this long, then wait until it reports the auto-lock.
    Idle(Duration),
}

/// What background threads saw: notices above the prompt and the clipboard.
#[derive(Default)]
struct Shared {
    notices: Mutex<Vec<String>>,
    clipboard: Mutex<Option<String>>,
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
fn line(text: &str) -> Input {
    Input::Line(text.to_owned())
}

/// A hidden line in a script.
///
/// ```text
/// vec![hidden(PASSWORD)]
/// ```
fn hidden(text: &str) -> Input {
    Input::Hidden(text.to_owned())
}

/// A scripted terminal that records everything printed.
struct FakeTerminal {
    inputs: VecDeque<Input>,
    clock: Arc<ManualClock>,
    shared: Arc<Shared>,
    stdout_is_terminal: bool,
    out: Vec<String>,
    err: Vec<String>,
    hidden_prompts: Vec<String>,
    /// The last value copied, kept after the clipboard is cleared.
    copied: Option<String>,
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
                    let deadline = Instant::now() + Duration::from_secs(5);
                    while self.shared.notices.lock().unwrap().is_empty() {
                        assert!(Instant::now() < deadline, "auto-lock never fired");
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
                input => return Some(input),
            }
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
            Some(Input::Hidden(_)) => panic!("hidden value read through visible prompt {prompt:?}"),
            Some(Input::Interrupt) => Err(TerminalError::Interrupted),
            Some(Input::Idle(_)) => unreachable!("handled in next"),
            None => Err(TerminalError::EndOfInput),
        }
    }

    /// Everything printed to stdout, one entry per `print`.
    ///
    /// ```text
    /// assert!(terminal.stdout().contains("secret added"));
    /// ```
    fn stdout(&self) -> String {
        self.out.join("\n")
    }

    /// Everything printed to stderr.
    ///
    /// ```text
    /// assert!(terminal.stderr().contains("wrong vaultname"));
    /// ```
    fn stderr(&self) -> String {
        self.err.join("\n")
    }

    /// What is on the fake clipboard.
    ///
    /// ```text
    /// assert_eq!(terminal.clipboard(), None);
    /// ```
    fn clipboard(&self) -> Option<String> {
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
            Some(Input::Line(line)) => panic!("visible line {line:?} read through hidden prompt"),
            Some(Input::Interrupt) => Err(TerminalError::Interrupted),
            Some(Input::Idle(_)) => unreachable!("handled in next"),
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
struct Fixture {
    dir: TempDir,
    clock: Arc<ManualClock>,
}

impl Fixture {
    /// An empty vault directory.
    ///
    /// ```text
    /// let fx = Fixture::new();
    /// ```
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            clock: Arc::new(ManualClock {
                start: Instant::now(),
                elapsed: Mutex::new(Duration::ZERO),
            }),
        }
    }

    /// A fixture with vault `alice` (master password [`PASSWORD`]) already created.
    ///
    /// ```text
    /// let fx = Fixture::with_alice();
    /// ```
    fn with_alice() -> Self {
        let fx = Self::new();
        let store = SqliteStore::new(fx.dir.path()).unwrap();
        let password = MasterPassword::new(PASSWORD.to_owned());
        Session::create_insecure_for_tests(store, "alice", &password, SessionConfig::default())
            .unwrap()
            .lock();
        fx
    }

    /// Runs `vault --vault-dir <dir> <args>` with `inputs` as the person's answers.
    ///
    /// ```text
    /// let (exit, terminal) = fx.run(&["unlock", "alice"], vec![hidden(PASSWORD)]);
    /// ```
    fn run(&self, args: &[&str], inputs: Vec<Input>) -> (Exit, FakeTerminal) {
        self.run_on(args, inputs, true)
    }

    /// Like [`Fixture::run`], but saying whether stdout is a terminal.
    ///
    /// ```text
    /// let (exit, terminal) = fx.run_on(&["unlock", "alice"], inputs, false);
    /// ```
    fn run_on(
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

    /// Unlocks `alice` and runs `commands` in the vault shell, with `answers` for the
    /// prompts the commands ask (in order, after all commands' own answers are inlined).
    ///
    /// ```text
    /// let (exit, t) = fx.shell(vec![line("list")]);
    /// ```
    fn shell(&self, script: Vec<Input>) -> (Exit, FakeTerminal) {
        let mut inputs = vec![hidden(PASSWORD)];
        inputs.extend(script);
        self.run(&["unlock", "alice"], inputs)
    }
}

/// The answers `save` asks for, for a secret with only a username and a password.
///
/// ```text
/// script.extend(save_answers("alice", "s3cret!"));
/// ```
fn save_answers(username: &str, password: &str) -> Vec<Input> {
    vec![
        line(username),
        hidden(password),
        line(""),  // URL
        line(""),  // notes
        line(""),  // tags
        line("n"), // no custom field
    ]
}

/// A script that saves `github` (user `alice`, password `s3cret!`) first.
///
/// ```text
/// let (exit, t) = fx.shell(with_github(vec![line("list")]));
/// ```
fn with_github(then: Vec<Input>) -> Vec<Input> {
    let mut script = vec![line("save github")];
    script.extend(save_answers("alice", "s3cret!"));
    script.extend(then);
    script
}

// --- unlock ---------------------------------------------------------------------------

#[test]
fn unlock_opens_the_vault_shell_and_lock_ends_it() {
    let fx = Fixture::with_alice();
    let (exit, t) = fx.shell(vec![line("lock")]);
    assert_eq!(exit, Exit::Success);
    assert!(t.out[0].starts_with("vault 'alice' unlocked"));
    assert_eq!(t.out.last().unwrap(), "vault locked");
    assert_eq!(t.hidden_prompts, ["Master password: "]);
}

#[test]
fn unlock_asks_for_the_vaultname_when_it_is_left_out() {
    let fx = Fixture::with_alice();
    let inputs = vec![line("alice"), hidden(PASSWORD), line("exit")];
    let (exit, _) = fx.run(&["unlock"], inputs);
    assert_eq!(exit, Exit::Success);
}

#[test]
fn a_wrong_master_password_can_be_retried() {
    let fx = Fixture::with_alice();
    let inputs = vec![hidden("wrong guess"), hidden(PASSWORD), line("lock")];
    let (exit, t) = fx.run(&["unlock", "alice"], inputs);
    assert_eq!(exit, Exit::Success);
    assert_eq!(t.stderr(), "vault: wrong vaultname or master password");
}

#[test]
fn three_wrong_master_passwords_give_up() {
    let fx = Fixture::with_alice();
    let inputs = vec![hidden("one"), hidden("two"), hidden("three")];
    let (exit, t) = fx.run(&["unlock", "alice"], inputs);
    assert_eq!(exit, Exit::Failure);
    assert_eq!(t.err.len(), 3);
}

#[test]
fn an_unknown_vaultname_fails_like_a_wrong_password() {
    let fx = Fixture::with_alice();
    let (_, unknown) = fx.run(&["unlock", "bob"], vec![hidden(PASSWORD)]);
    let (_, wrong) = fx.run(&["unlock", "alice"], vec![hidden("wrong guess")]);
    assert_eq!(unknown.err[0], wrong.err[0]);
}

#[test]
fn an_invalid_vaultname_is_refused_before_any_password_prompt() {
    let fx = Fixture::with_alice();
    let (exit, t) = fx.run(&["unlock", "../etc/passwd"], vec![]);
    assert_eq!(exit, Exit::Failure);
    assert!(t.hidden_prompts.is_empty());
}

#[test]
fn ctrl_d_at_the_prompt_locks_the_vault() {
    let fx = Fixture::with_alice();
    let (exit, t) = fx.shell(vec![]);
    assert_eq!(exit, Exit::Success);
    assert_eq!(t.out.last().unwrap(), "vault locked");
}

// --- init -----------------------------------------------------------------------------

#[test]
fn init_creates_a_vault_after_retrying_mismatched_and_weak_passwords() {
    let fx = Fixture::new();
    let inputs = vec![
        hidden("first try at it"),
        hidden("first try at itx"), // mismatch
        hidden("short"),
        hidden("short"), // too weak
        hidden(PASSWORD),
        hidden(PASSWORD),
        line("lock"),
    ];
    let (exit, t) = fx.run(&["init", "carol"], inputs);
    assert_eq!(exit, Exit::Success, "{}", t.stderr());
    assert_eq!(
        t.err,
        [
            "vault: master passwords don't match",
            "vault: master password must be at least 12 characters"
        ]
    );
    let (exit, _) = fx.run(&["unlock", "carol"], vec![hidden(PASSWORD)]);
    assert_eq!(exit, Exit::Success);
}

#[test]
fn init_refuses_a_taken_vaultname_before_any_password_prompt() {
    let fx = Fixture::with_alice();
    let (exit, t) = fx.run(&["init", "alice"], vec![]);
    assert_eq!(exit, Exit::Failure);
    assert!(t.hidden_prompts.is_empty());
    assert!(t.stderr().contains("already exists"), "{}", t.stderr());
}

// --- save / get / list / rm -------------------------------------------------------------

#[test]
fn saved_secret_is_shown_masked_by_get() {
    let fx = Fixture::with_alice();
    let (exit, t) = fx.shell(with_github(vec![line("get github")]));
    assert_eq!(exit, Exit::Success);
    assert!(t.stdout().contains("secret added"));
    let view = t.out.iter().find(|o| o.starts_with("title:")).unwrap();
    assert!(view.contains("username: alice"));
    assert!(view.contains("password: *"));
    assert!(!t.stdout().contains("s3cret!"));
}

#[test]
fn get_show_reveals_hidden_fields_on_a_terminal() {
    let fx = Fixture::with_alice();
    let (_, t) = fx.shell(with_github(vec![line("get github --show")]));
    assert!(t.stdout().contains("password: s3cret!"));
}

#[test]
fn get_show_is_refused_when_stdout_is_not_a_terminal() {
    let fx = Fixture::with_alice();
    let mut inputs = vec![hidden(PASSWORD)];
    inputs.extend(with_github(vec![line("get github --show")]));
    let (_, t) = fx.run_on(&["unlock", "alice"], inputs, false);
    assert!(!t.stdout().contains("s3cret!"));
    assert!(t.stderr().contains("only shown on a terminal"));
}

#[test]
fn get_copy_puts_the_password_on_the_clipboard_and_lock_clears_it() {
    let fx = Fixture::with_alice();
    let (_, t) = fx.shell(with_github(vec![line("get github --copy")]));
    assert!(t.stdout().contains("password copied"));
    assert!(!t.stdout().contains("s3cret!"));
    assert_eq!(t.copied.as_deref(), Some("s3cret!"));
    assert_eq!(t.clipboard(), None, "cleared when the shell ended");
}

#[test]
fn get_show_and_copy_cannot_be_combined() {
    let fx = Fixture::with_alice();
    let (_, t) = fx.shell(with_github(vec![line("get github --show --copy")]));
    assert!(t.stderr().contains("cannot be used with"), "{}", t.stderr());
    assert!(!t.stdout().contains("s3cret!"));
}

#[test]
fn an_empty_password_is_generated() {
    let fx = Fixture::with_alice();
    let mut script = vec![line("save wifi")];
    script.extend(save_answers("", ""));
    script.push(line("get wifi --show"));
    let (_, t) = fx.shell(script);
    assert!(t.stdout().contains("generated a 24-character password"));
    let view = t.out.iter().find(|o| o.starts_with("title:")).unwrap();
    let password = view
        .lines()
        .find_map(|l| l.strip_prefix("password: "))
        .unwrap();
    assert_eq!(password.chars().count(), 24);
}

#[test]
fn save_asks_for_every_field_and_custom_fields() {
    let fx = Fixture::with_alice();
    let script = vec![
        line("save \"my bank\""),
        line("alice"),
        hidden("s3cret!"),
        line("https://bank.example"),
        line("call before travelling"),
        line("money, important"),
        line("y"),
        line("recovery code"),
        line("y"),
        hidden("1234-5678"),
        line("y"),
        line("branch"),
        line("n"),
        line("Tallinn"),
        line("n"),
        line("get \"my bank\""),
    ];
    let (_, t) = fx.shell(script);
    let view = t.out.iter().find(|o| o.starts_with("title:")).unwrap();
    for expected in [
        "title:         my bank",
        "url:           https://bank.example",
        "tags:          money, important",
        "notes:         call before travelling",
        "recovery code: *",
        "branch:        Tallinn",
    ] {
        assert!(view.contains(expected), "missing {expected:?} in\n{view}");
    }
    assert_eq!(
        t.hidden_prompts,
        [
            "Master password: ",
            "Password (empty to generate): ",
            "Value: "
        ]
    );
}

#[test]
fn saving_an_existing_title_asks_before_replacing() {
    let fx = Fixture::with_alice();
    let mut then = vec![line("save GitHub"), line("n")];
    then.push(line("save github"));
    then.push(line("y"));
    then.extend(save_answers("bob", "other"));
    then.push(line("get github"));
    let (_, t) = fx.shell(with_github(then));
    assert!(t.stdout().contains("not saved"));
    assert!(t.stdout().contains("secret replaced"));
    assert!(t.stdout().contains("username: bob"));
}

#[test]
fn ctrl_c_during_save_cancels_it_and_the_shell_goes_on() {
    let fx = Fixture::with_alice();
    let script = vec![line("save github"), Input::Interrupt, line("list")];
    let (exit, t) = fx.shell(script);
    assert_eq!(exit, Exit::Success);
    assert!(t.stderr().contains("vault: cancelled"));
    assert!(t.stdout().contains("no secrets yet"));
}

#[test]
fn an_invalid_field_is_reported_and_nothing_is_saved() {
    let fx = Fixture::with_alice();
    let mut script = vec![line("save x")];
    script.extend(save_answers("alice", "s3cret!"));
    script[2] = hidden(&"x".repeat(1025));
    script.push(line("list"));
    let (_, t) = fx.shell(script);
    assert!(t.stderr().contains("password"), "{}", t.stderr());
    assert!(t.stdout().contains("no secrets yet"));
}

#[test]
fn list_shows_saved_secrets_without_hidden_fields() {
    let fx = Fixture::with_alice();
    let (_, t) = fx.shell(with_github(vec![line("list")]));
    let table = t.out.iter().find(|o| o.starts_with("TITLE")).unwrap();
    assert!(table.contains("github  alice"));
    assert!(!table.contains("s3cret!"));
}

#[test]
fn rm_removes_a_secret_after_confirming() {
    let fx = Fixture::with_alice();
    let then = vec![
        line("rm github"),
        line("n"),
        line("rm github"),
        line("yes"),
        line("list"),
    ];
    let (_, t) = fx.shell(with_github(then));
    assert!(t.stdout().contains("not removed"));
    assert!(t.stdout().contains("secret removed"));
    assert!(t.stdout().contains("no secrets yet"));
}

#[test]
fn rm_of_an_unknown_title_says_so_without_asking() {
    let fx = Fixture::with_alice();
    let (_, t) = fx.shell(vec![line("rm nothing"), line("lock")]);
    assert_eq!(t.stderr(), "vault: no secret with this title");
}

#[test]
fn secrets_survive_lock_and_unlock() {
    let fx = Fixture::with_alice();
    fx.shell(with_github(vec![line("lock")]));
    let (_, t) = fx.shell(vec![line("get github")]);
    assert!(t.stdout().contains("username: alice"));
}

// --- passwd ---------------------------------------------------------------------------

#[test]
fn passwd_changes_the_master_password() {
    let fx = Fixture::with_alice();
    let script = vec![
        line("passwd"),
        hidden(PASSWORD),
        hidden("tr0ub4dor & 3 staples"),
        hidden("tr0ub4dor & 3 staples"),
        line("lock"),
    ];
    let (_, t) = fx.shell(script);
    assert!(
        t.stdout().contains("master password changed"),
        "{}",
        t.stderr()
    );
    let (exit, _) = fx.run(&["unlock", "alice"], vec![hidden("tr0ub4dor & 3 staples")]);
    assert_eq!(exit, Exit::Success);
}

#[test]
fn passwd_with_a_wrong_current_password_changes_nothing() {
    let fx = Fixture::with_alice();
    let script = vec![
        line("passwd"),
        hidden("wrong guess"),
        hidden("tr0ub4dor & 3 staples"),
        hidden("tr0ub4dor & 3 staples"),
        line("lock"),
    ];
    let (_, t) = fx.shell(script);
    assert!(t.stderr().contains("wrong vaultname or master password"));
    let (exit, _) = fx.run(&["unlock", "alice"], vec![hidden(PASSWORD)]);
    assert_eq!(exit, Exit::Success);
}

// --- auto-lock ------------------------------------------------------------------------

#[test]
fn idle_shell_auto_locks_and_exits_on_the_next_input() {
    let fx = Fixture::with_alice();
    let script = vec![Input::Idle(Duration::from_secs(5 * 60)), line("list")];
    let (exit, t) = fx.shell(script);
    assert_eq!(exit, Exit::Failure);
    let notices = t.shared.notices.lock().unwrap().clone();
    assert_eq!(notices, ["vault locked (idle); press Enter to close"]);
    assert!(
        !t.stdout().contains("TITLE"),
        "list must not run after auto-lock"
    );
}

#[test]
fn idle_timeout_can_be_set_per_unlock() {
    let fx = Fixture::with_alice();
    let inputs = vec![
        hidden(PASSWORD),
        Input::Idle(Duration::from_secs(60)),
        line("list"),
    ];
    let (exit, _) = fx.run(&["unlock", "alice", "--idle-timeout", "1"], inputs);
    assert_eq!(exit, Exit::Failure);
}

#[test]
fn auto_lock_during_a_prompt_fails_the_command_and_exits() {
    let fx = Fixture::with_alice();
    let mut script = vec![
        line("save github"),
        Input::Idle(Duration::from_secs(5 * 60)),
    ];
    script.extend(save_answers("alice", "s3cret!"));
    let (exit, t) = fx.shell(script);
    assert_eq!(exit, Exit::Failure);
    assert!(t.stderr().contains("vault: vault is locked"));
    let (_, after) = fx.shell(vec![line("list")]);
    assert!(after.stdout().contains("no secrets yet"));
}

#[test]
fn auto_lock_clears_the_clipboard() {
    let fx = Fixture::with_alice();
    let then = vec![
        line("get github --copy"),
        Input::Idle(Duration::from_secs(5 * 60)),
    ];
    let (_, t) = fx.shell(with_github(then));
    assert_eq!(t.clipboard(), None);
}

#[test]
fn idle_timeout_out_of_range_is_a_usage_error() {
    let fx = Fixture::with_alice();
    let (exit, _) = fx.run(&["unlock", "alice", "--idle-timeout", "61"], vec![]);
    assert_eq!(exit, Exit::Usage);
}

// --- command line ---------------------------------------------------------------------

#[test]
fn shell_commands_at_the_os_shell_point_to_unlock() {
    let fx = Fixture::with_alice();
    let (exit, t) = fx.run(&["list"], vec![]);
    assert_eq!(exit, Exit::Usage);
    assert_eq!(
        t.stderr(),
        "vault: `list` works inside the vault shell; run `vault unlock` first"
    );
}

#[test]
fn gen_prints_a_password_of_the_requested_length() {
    let fx = Fixture::new();
    let (exit, t) = fx.run(&["gen", "--length", "30"], vec![]);
    assert_eq!(exit, Exit::Success);
    assert_eq!(t.out[0].chars().count(), 30);
}

#[test]
fn gen_refuses_a_length_out_of_range() {
    let fx = Fixture::new();
    let (exit, t) = fx.run(&["gen", "--length", "5"], vec![]);
    assert_eq!(exit, Exit::Failure);
    assert_eq!(
        t.stderr(),
        "vault: password length must be 12-128 characters"
    );
}

#[test]
fn gen_in_the_shell_offers_to_copy() {
    let fx = Fixture::with_alice();
    let (_, t) = fx.shell(vec![line("gen"), line("y")]);
    assert_eq!(t.out[1].chars().count(), 24);
    assert!(
        t.stdout()
            .contains("copied; the clipboard clears in 20 seconds")
    );
}

#[test]
fn unknown_commands_and_bad_quotes_are_reported_and_the_shell_goes_on() {
    let fx = Fixture::with_alice();
    let script = vec![line("frobnicate"), line("get \"unclosed"), line("lock")];
    let (exit, t) = fx.shell(script);
    assert_eq!(exit, Exit::Success);
    assert!(t.stderr().contains("unrecognized subcommand"));
    assert!(t.stderr().contains("vault: unbalanced quotes"));
}

#[test]
fn help_in_the_shell_lists_the_commands() {
    let fx = Fixture::with_alice();
    let (_, t) = fx.shell(vec![line("help")]);
    let help = t
        .out
        .iter()
        .find(|o| o.contains("passwd"))
        .expect("help printed");
    for command in ["get", "save", "list", "rm", "gen", "lock"] {
        assert!(help.contains(command), "{command} missing from help");
    }
}
