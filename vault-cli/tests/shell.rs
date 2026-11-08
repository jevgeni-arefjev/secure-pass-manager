//! Behaviour of the `vault` CLI and its vault shell, driven through `shell::run` with a
//! scripted fake terminal and a manual clock (`common`).

mod common;

use std::time::Duration;

use common::{FakeTerminal, Fixture, Input, PASSWORD, hidden, line};
use vault_cli::shell::Exit;
use vault_cli::terminal::TerminalError;
use vault_core::crypto::MasterPassword;
use vault_core::session;
use vault_core::storage::FileStore;

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
fn a_vaultname_with_surrounding_spaces_opens_the_same_vault() {
    let fx = Fixture::with_alice();
    let (exit, t) = fx.run(&["unlock", " alice "], vec![hidden(PASSWORD), line("lock")]);
    assert_eq!(exit, Exit::Success, "{}", t.stderr());
    assert!(t.out[0].starts_with("vault 'alice' unlocked"));
    let inputs = vec![line("  alice"), hidden(PASSWORD), line("lock")];
    let (exit, _) = fx.run(&["unlock"], inputs);
    assert_eq!(exit, Exit::Success);
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
        hidden("short"),            // too weak: refused before the repeat prompt
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
fn init_rejects_a_weak_password_before_asking_to_repeat_it() {
    let fx = Fixture::new();
    let inputs = vec![
        hidden("short"),
        hidden(PASSWORD),
        hidden(PASSWORD),
        line("lock"),
    ];
    let (exit, t) = fx.run(&["init", "carol"], inputs);
    assert_eq!(exit, Exit::Success, "{}", t.stderr());
    assert_eq!(
        t.hidden_prompts,
        [
            "New master password: ",
            "New master password: ",
            "Repeat master password: "
        ]
    );
    assert_eq!(
        t.err,
        ["vault: master password must be at least 12 characters"]
    );
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
fn every_whole_secret_problem_of_a_refused_save_is_printed() {
    let fx = Fixture::with_alice();
    let tags: Vec<String> = (1..=33).map(|i| format!("t{i}")).collect();
    let mut script = vec![
        line("save x"),
        line("alice"),
        hidden("s3cret!"),
        line(""), // URL
        line(""), // notes
        line(&tags.join(",")),
    ];
    for i in 1..=33 {
        script.extend([line("y"), line(&format!("f{i}")), line("n"), line("v")]);
    }
    script.extend([line("n"), line("list")]);
    let (exit, t) = fx.shell(script);
    assert_eq!(exit, Exit::Success);
    assert_eq!(
        t.stderr(),
        "vault: secret not saved:\n\
        \x20 tags: a secret can have at most 32 tags\n\
        \x20 custom fields: a secret can have at most 32 custom fields"
    );
    assert!(t.stdout().contains("no secrets yet"));
}

#[test]
fn a_refused_paste_cancels_save_with_its_message_and_the_shell_goes_on() {
    let fx = Fixture::with_alice();
    let script = vec![
        line("save github"),
        line("alice"),                                     // username
        Input::HiddenRefused(TerminalError::PasteTooLong), // password
        line("list"),
    ];
    let (exit, t) = fx.shell(script);
    assert_eq!(exit, Exit::Success);
    assert!(
        t.stderr()
            .contains("pasted text was longer than 1024 characters; nothing was entered"),
        "{}",
        t.stderr()
    );
    assert!(t.stdout().contains("no secrets yet"));
}

#[test]
fn a_full_vault_refuses_a_save_and_the_shell_goes_on() {
    let fx = Fixture::with_alice();
    let store = FileStore::new(fx.dir.path()).unwrap();
    session::fill_vault_for_tests(&store, "alice", &MasterPassword::new(PASSWORD.to_owned()))
        .unwrap();
    let mut script = vec![line("save github")];
    script.extend(save_answers("alice", "s3cret!"));
    script.push(line("get github"));
    script.push(line("lock"));
    let (exit, t) = fx.shell(script);
    assert_eq!(exit, Exit::Success);
    assert!(
        t.stderr().contains("vault: vault is full"),
        "{}",
        t.stderr()
    );
    assert!(
        t.stderr().contains("no secret with this title"),
        "{}",
        t.stderr()
    );
    assert_eq!(t.out.last().unwrap(), "vault locked");
}

#[cfg(unix)]
#[test]
fn a_storage_failure_is_shown_with_its_cause_kind() {
    use std::os::unix::fs::PermissionsExt;

    let fx = Fixture::with_alice();
    let home = fx.dir.path().join("alice");
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o500)).unwrap();
    if std::fs::write(home.join("probe"), b"").is_ok() {
        // Root ignores permissions (as in CI's Fedora container): nothing to test.
        return;
    }
    let mut script = vec![line("save github")];
    script.extend(save_answers("alice", "s3cret!"));
    script.push(line("lock"));

    let (exit, t) = fx.shell(script);
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();

    assert_eq!(exit, Exit::Success);
    assert_eq!(
        t.stderr(),
        "vault: vault storage failed (permission denied)"
    );
}

#[test]
fn an_invalid_title_is_refused_before_any_field_prompt() {
    let fx = Fixture::with_alice();
    let title = "x".repeat(65);
    let script = vec![line(&format!("save {title}")), line("list")];
    let (exit, t) = fx.shell(script);
    assert_eq!(exit, Exit::Success);
    assert_eq!(
        t.stderr(),
        "vault: secret not saved:\n  title: title must be 1-64 characters, without control or formatting characters"
    );
    assert_eq!(t.hidden_prompts, ["Master password: "]);
    assert!(t.stdout().contains("no secrets yet"));
}

#[test]
fn an_invalid_answer_is_asked_again_with_the_reason() {
    let fx = Fixture::with_alice();
    let script = vec![
        line("save github"),
        line("al\u{1b}ice"), // username: refused
        line("alice"),
        hidden("bell\u{7}"), // password: refused
        hidden("s3cret!"),
        line("ftp://github.com"), // URL: refused
        line("github.com"),
        line(""),  // notes
        line(""),  // tags
        line("n"), // no custom field
        line("get github --show"),
    ];
    let (exit, t) = fx.shell(script);
    assert_eq!(exit, Exit::Success);
    assert_eq!(
        t.err,
        [
            "vault: username: username must be 1-256 characters, without control or formatting characters",
            "vault: password: password must be 1-1024 characters, without control characters",
            "vault: URL: URL must be an http:// or https:// address with a host, or a bare host such as github.com; keep other addresses in notes or a custom field",
        ]
    );
    assert_eq!(
        t.hidden_prompts,
        [
            "Master password: ",
            "Password (empty to generate): ",
            "Password (empty to generate): "
        ]
    );
    assert!(
        !t.stderr().contains("bell"),
        "a refused value is never echoed"
    );
    assert_eq!(t.out.iter().filter(|o| *o == "secret added").count(), 1);
    let view = t.out.iter().find(|o| o.starts_with("title:")).unwrap();
    assert!(view.contains("username: alice"), "{view}");
    assert!(view.contains("password: s3cret!"), "{view}");
    assert!(view.contains("url:      github.com"), "{view}");
}

#[test]
fn a_duplicate_tag_or_custom_field_name_is_caught_when_entered() {
    let fx = Fixture::with_alice();
    let script = vec![
        line("save github"),
        line("alice"),
        hidden("s3cret!"),
        line(""),
        line(""),
        line("work, dev, WORK"), // tags: refused, the third repeats the first
        line("work, dev"),
        line("y"),
        line("pin"),
        line("y"),
        hidden("1234"),
        line("y"),
        line("PIN"),      // repeats the first custom field
        line("username"), // a standard field name
        line("region"),
        line("n"),
        line("eu"),
        line("n"),
        line("get github"),
    ];
    let (exit, t) = fx.shell(script);
    assert_eq!(exit, Exit::Success);
    assert_eq!(
        t.err,
        [
            "vault: tag 3: tags must be unique, ignoring case",
            "vault: custom field 2 name: custom field names must be unique and differ from the standard fields",
            "vault: custom field 2 name: custom field names must be unique and differ from the standard fields",
        ]
    );
    let view = t.out.iter().find(|o| o.starts_with("title:")).unwrap();
    assert!(view.contains("tags:     work, dev"), "{view}");
    assert!(view.contains("pin:      *"), "{view}");
    assert!(view.contains("region:   eu"), "{view}");
}

#[test]
fn an_empty_custom_field_value_is_asked_again_hidden_or_not() {
    let fx = Fixture::with_alice();
    let script = vec![
        line("save github"),
        line(""), // username: not set
        hidden("s3cret!"),
        line(""), // URL: not set
        line(""), // notes: not set
        line(""), // tags: none
        line("y"),
        line("pin"),
        line("y"),
        hidden(""), // empty hidden value: refused
        hidden("1234"),
        line("y"),
        line("region"),
        line("n"),
        line("   "), // empty value: refused
        line("eu"),
        line("n"),
        line("get github"),
    ];
    let (exit, t) = fx.shell(script);
    assert_eq!(exit, Exit::Success);
    let reason = "custom field values must be 1-1024 characters, without control or formatting characters (hidden: 1-1024, without control characters)";
    assert_eq!(
        t.err,
        [
            format!("vault: custom field 1 value: {reason}"),
            format!("vault: custom field 2 value: {reason}"),
        ]
    );
    assert_eq!(
        t.hidden_prompts,
        [
            "Master password: ",
            "Password (empty to generate): ",
            "Value: ",
            "Value: "
        ]
    );
    let view = t.out.iter().find(|o| o.starts_with("title:")).unwrap();
    assert!(!view.contains("username"), "{view}");
    assert!(!view.contains("url"), "{view}");
    assert!(view.contains("region:   eu"), "{view}");
}

#[test]
fn ctrl_c_at_a_re_asked_prompt_cancels_the_save() {
    let fx = Fixture::with_alice();
    let script = vec![
        line("save github"),
        line("alice"),
        hidden("bell\u{7}"), // refused
        Input::Interrupt,
        line("list"),
    ];
    let (exit, t) = fx.shell(script);
    assert_eq!(exit, Exit::Success);
    assert_eq!(t.err.last().unwrap(), "vault: cancelled");
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

#[test]
fn passwd_refuses_a_new_master_password_with_control_characters() {
    let fx = Fixture::with_alice();
    // The real hidden prompt drops control characters; a pasted one could still get
    // through another front end, so the core rule is checked here too.
    let script = vec![
        line("passwd"),
        hidden(PASSWORD),
        hidden("tr0ub4dor\u{1b}3 staples"),
        line("lock"),
    ];
    let (_, t) = fx.shell(script);
    assert!(
        t.stderr()
            .contains("master password must not contain control characters"),
        "{}",
        t.stderr()
    );
    assert!(!t.stderr().contains("tr0ub4dor"));
}

#[test]
fn passwd_rejects_a_weak_new_password_before_asking_to_repeat_it() {
    let fx = Fixture::with_alice();
    let script = vec![
        line("passwd"),
        hidden(PASSWORD),
        hidden("short"),
        line("lock"),
    ];
    let (_, t) = fx.shell(script);
    assert!(
        t.stderr()
            .contains("master password must be at least 12 characters"),
        "{}",
        t.stderr()
    );
    assert!(
        !t.hidden_prompts.iter().any(|p| p.starts_with("Repeat")),
        "{:?}",
        t.hidden_prompts
    );
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
fn a_panic_in_the_vault_shell_wipes_the_session_and_clears_the_clipboard() {
    let fx = Fixture::with_alice();
    let (exit, t) = fx.shell(with_github(vec![line("get github --copy"), Input::Panic]));
    assert_eq!(exit, Exit::Failure);
    assert_eq!(t.copied.as_deref(), Some("s3cret!"));
    assert_eq!(t.clipboard(), None, "cleared after the panic");
    assert_eq!(t.out.last().unwrap(), "vault locked");

    // No audit event for a panic (ADR-0014): no "locked" after the reveal.
    let (_, t) = fx.shell(vec![line("log")]);
    assert_eq!(
        logged_events(&t),
        [
            "unlocked",
            "secret revealed 'github'",
            "secret added 'github'",
            "unlocked",
            "locked",
            "vault created",
        ]
    );
}

#[test]
fn a_panic_in_the_auto_lock_watcher_wipes_the_session_and_ends_the_shell() {
    let fx = Fixture::with_alice();
    let (exit, t) = fx.shell(with_github(vec![
        line("get github --copy"),
        Input::ClockPanics,
        line("list"),
    ]));
    assert_eq!(exit, Exit::Failure);
    assert_eq!(t.clipboard(), None, "cleared after the panic");
    assert_eq!(
        *t.shared.notices.lock().unwrap(),
        ["vault locked (internal error); press Enter to close"]
    );
    assert!(!t.stdout().contains("no secrets"), "list didn't run");
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
    for command in ["get", "save", "list", "rm", "gen", "backup", "lock"] {
        assert!(help.contains(command), "{command} missing from help");
    }
}

// --- backup ---------------------------------------------------------------------------

#[test]
fn backup_writes_the_vault_file_and_says_which_revision_it_holds() {
    let fx = Fixture::with_alice();
    let elsewhere = tempfile::tempdir().unwrap();
    let path = elsewhere.path().join("alice.vault");
    let (exit, t) = fx.shell(with_github(vec![
        line(&format!("backup {}", path.display())),
        line("lock"),
    ]));
    assert_eq!(exit, Exit::Success, "{}", t.stderr());
    assert!(t.stdout().contains(&format!(
        "Backup written to {} (revision 1). It opens with the master password this vault has now.",
        path.display()
    )));
    assert_eq!(
        std::fs::read(&path).unwrap(),
        std::fs::read(fx.dir.path().join("alice/secrets.vault")).unwrap()
    );
}

#[test]
fn backup_refuses_an_existing_file_and_the_shell_goes_on() {
    let fx = Fixture::with_alice();
    let elsewhere = tempfile::tempdir().unwrap();
    let path = elsewhere.path().join("taken");
    std::fs::write(&path, b"keep me").unwrap();
    let (exit, t) = fx.shell(vec![
        line(&format!("backup {}", path.display())),
        line("lock"),
    ]);
    assert_eq!(exit, Exit::Success);
    assert_eq!(
        t.stderr(),
        "vault: something already exists at the backup path; a backup never overwrites"
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"keep me");
}

#[test]
fn backup_refuses_a_path_inside_the_vault_directory() {
    let fx = Fixture::with_alice();
    let path = fx.dir.path().join("alice.vault");
    let (_, t) = fx.shell(vec![line(&format!("backup {}", path.display()))]);
    assert_eq!(
        t.stderr(),
        "vault: a backup can't be written inside the vault directory"
    );
    assert!(!path.exists());
}

#[test]
fn backup_is_shown_in_the_log_with_its_revision() {
    let fx = Fixture::with_alice();
    let elsewhere = tempfile::tempdir().unwrap();
    let path = elsewhere.path().join("alice.vault");
    let (_, t) = fx.shell(vec![
        line(&format!("backup {}", path.display())),
        line("log"),
    ]);
    assert_eq!(logged_events(&t)[0], "backup created (revision 0)");
    assert!(!t.out.last().unwrap().contains("alice.vault"));
}

#[test]
fn backup_outside_the_vault_shell_points_to_unlock() {
    let fx = Fixture::with_alice();
    let (exit, t) = fx.run(&["backup", "/tmp/alice.vault"], vec![]);
    assert_eq!(exit, Exit::Usage);
    assert!(t.stderr().contains("works inside the vault shell"));
}

// --- log ------------------------------------------------------------------------------

/// The event descriptions of the last `log` output, without their timestamps, newest
/// first.
///
/// ```text
/// assert_eq!(logged_events(&t), ["unlocked", "locked", "vault created"]);
/// ```
fn logged_events(t: &FakeTerminal) -> Vec<String> {
    let log = t
        .out
        .iter()
        .rev()
        .find(|out| out.contains("vault created"))
        .expect("no log output");
    log.lines()
        .map(|line| match line.get(..21) {
            // "YYYY-MM-DD HH:MM:SS  "
            Some(time) if time.as_bytes()[4] == b'-' && time.ends_with("  ") => {
                line[21..].to_owned()
            }
            _ => line.to_owned(),
        })
        .collect()
}

#[test]
fn log_shows_reveals_and_changes_newest_first_but_not_masked_views() {
    let fx = Fixture::with_alice();
    let (exit, t) = fx.shell(with_github(vec![
        line("get github"),
        line("list"),
        line("get github --show"),
        line("get github --copy"),
        line("log"),
    ]));
    assert_eq!(exit, Exit::Success);
    assert_eq!(
        logged_events(&t),
        [
            "secret revealed 'github'",
            "secret revealed 'github'",
            "secret added 'github'",
            "unlocked",
            "locked",
            "vault created",
        ]
    );
}

#[test]
fn log_limit_shows_only_the_newest_events() {
    let fx = Fixture::with_alice();
    let (_, t) = fx.shell(vec![line("log --limit 1"), line("lock")]);
    assert!(t.stdout().lines().any(|l| l.ends_with("  unlocked")));
    assert!(!t.stdout().contains("vault created"));
}

#[test]
fn log_shows_a_failed_unlock_of_this_vault() {
    let fx = Fixture::with_alice();
    let (_, t) = fx.run(
        &["unlock", "alice"],
        vec![hidden("wrong guess"), hidden(PASSWORD), line("log")],
    );
    assert_eq!(
        logged_events(&t)[..2],
        ["unlocked", "unlock failed (wrong master password)"]
    );
}

#[test]
fn log_shows_lines_that_do_not_parse_as_unreadable() {
    let fx = Fixture::with_alice();
    let log = fx.dir.path().join("alice/audit.log");
    let mut bytes = std::fs::read(&log).unwrap();
    bytes.extend_from_slice(b"\x1b[2J garbage\n");
    std::fs::write(&log, bytes).unwrap();

    let (_, t) = fx.shell(vec![line("log")]);
    let events = logged_events(&t);
    assert_eq!(events[1], "<unreadable event>");
    assert!(!t.stdout().contains('\u{1b}'));
}

#[test]
fn log_outside_the_vault_shell_points_to_unlock() {
    let fx = Fixture::with_alice();
    let (exit, t) = fx.run(&["log"], vec![]);
    assert_eq!(exit, Exit::Usage);
    assert!(t.stderr().contains("works inside the vault shell"));
}
