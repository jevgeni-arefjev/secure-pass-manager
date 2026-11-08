//! End to end: no master password (right or wrong, weak or new) and no hidden field
//! value reaches what the CLI prints, its diagnostics or the audit log, across whole
//! `init` and `unlock` sessions driven through `shell::run`.
//!
//! Diagnostics are captured at every level with every field, through the default
//! `tracing` formatter, which is more than the CLI's own sentences ever show.

mod common;

use std::io::Write;
use std::sync::{Mutex, Once};

use common::{FakeTerminal, Fixture, hidden, line};
use tracing::Level;
use vault_cli::shell::Exit;

/// Alice's master password.
const MASTER: &str = "Unl0ck-Master-Qz7#Lp";
/// A wrong master password typed at unlock.
const WRONG_MASTER: &str = "Wr0ng-Guess-Hv3$Tk";
/// A master password `init` refuses as too weak.
const INIT_WEAK: &str = "Wk-Init-9j";
/// The master password `init` finally takes.
const INIT_MASTER: &str = "Init-Master-Fx2@Rw";
/// A repeat at `init` that doesn't match [`INIT_MASTER`].
const INIT_MISMATCH: &str = "Init-Mismatch-Jd5^Ce";
/// The password saved in secret `github`.
const SAVED_PASSWORD: &str = "S4ved-Passw0rd-Mn8!";
/// A password `save` refuses: the text before its control character.
const REFUSED_PASSWORD: &str = "Refused-Passw0rd-Ub2";
/// The hidden custom field value saved in secret `github`.
const HIDDEN_VALUE: &str = "R3covery-Code-Yt6%";
/// A hidden custom field value `save` refuses: the text before its control character.
const REFUSED_HIDDEN: &str = "Refused-Hidden-Kc5";
/// A wrong current master password typed at `passwd`.
const WRONG_CURRENT: &str = "Wr0ng-Current-Zp4&";
/// A new master password `passwd` refuses as too weak.
const WEAK_NEW: &str = "Wk-New-3dq";
/// The new master password `passwd` takes.
const NEW_MASTER: &str = "N3w-Master-Gb9*Ws";

/// Every master password and hidden field value typed in the sessions below.
const TYPED_VALUES: [&str; 12] = [
    MASTER,
    WRONG_MASTER,
    INIT_WEAK,
    INIT_MASTER,
    INIT_MISMATCH,
    SAVED_PASSWORD,
    REFUSED_PASSWORD,
    HIDDEN_VALUE,
    REFUSED_HIDDEN,
    WRONG_CURRENT,
    WEAK_NEW,
    NEW_MASTER,
];

/// Everything logged through `tracing` by any thread of this test binary.
static LOGS: Mutex<Vec<u8>> = Mutex::new(Vec::new());

/// A `tracing` writer appending to [`LOGS`].
struct CapturedLogs;

impl Write for CapturedLogs {
    /// Appends `buf` to [`LOGS`].
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        LOGS.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    /// Nothing to flush: writes go straight to memory.
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Installs a global subscriber writing every event, at every level and with all its
/// fields, to [`LOGS`]; global so the auto-lock watcher thread is captured too.
///
/// Security: this sees more than the CLI's own sentences ever print, so a typed value
/// in any field of any diagnostic is caught, not only in what reaches stderr.
///
/// ```text
/// capture_diagnostics();
/// ```
fn capture_diagnostics() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_max_level(Level::TRACE)
            .with_writer(|| CapturedLogs)
            .init();
    });
}

/// Panics if any of [`TYPED_VALUES`] appears in `text`, naming the `place` it was
/// found in.
///
/// Security: a whole-value match; a refused value is listed without its control
/// character, so an escaped echo of it is still found.
///
/// ```text
/// assert_none_typed("stdout of unlock", &t.stdout());
/// ```
fn assert_none_typed(place: &str, text: &str) {
    for value in TYPED_VALUES {
        assert!(
            !text.contains(value),
            "typed value {value:?} found in {place}:\n{text}"
        );
    }
}

/// Checks everything `t` printed to stdout or stderr or showed above the prompt, naming
/// the `run` of the CLI in the failure.
///
/// Security: covers every way the CLI writes to the person except the clipboard.
///
/// ```text
/// assert_terminal_clean("init", &t);
/// ```
fn assert_terminal_clean(run: &str, t: &FakeTerminal) {
    assert_none_typed(&format!("stdout of {run}"), &t.stdout());
    assert_none_typed(&format!("stderr of {run}"), &t.stderr());
    assert_none_typed(&format!("notices of {run}"), &t.notices());
}

/// `vault init carol`: a weak master password, then a mismatched repeat, then a
/// match.
///
/// ```text
/// let t = init_carol(&fx);
/// ```
fn init_carol(fx: &Fixture) -> FakeTerminal {
    let inputs = vec![
        hidden(INIT_WEAK),
        hidden(INIT_MASTER),
        hidden(INIT_MISMATCH),
        hidden(INIT_MASTER),
        hidden(INIT_MASTER),
        line("lock"),
    ];
    let (exit, t) = fx.run(&["init", "carol"], inputs);
    assert_eq!(exit, Exit::Success, "{}", t.stderr());
    assert_eq!(
        t.err,
        [
            "vault: master password must be at least 12 characters",
            "vault: master passwords don't match",
        ]
    );
    t
}

/// `vault unlock alice` with stdout not a terminal: a wrong master password, then
/// `save` (refused password and hidden field first), `get`, `get --show`, three
/// `passwd`s (wrong current, weak new, success), `backup` and `log`.
///
/// ```text
/// let t = alice_session(&fx, &backup_path);
/// ```
fn alice_session(fx: &Fixture, backup: &std::path::Path) -> FakeTerminal {
    let inputs = vec![
        hidden(WRONG_MASTER),
        hidden(MASTER),
        // save: a refused password and hidden field value, each asked again
        line("save github"),
        line("alice"),
        hidden(&format!("{REFUSED_PASSWORD}\u{7}")),
        hidden(SAVED_PASSWORD),
        line(""), // URL
        line(""), // notes
        line(""), // tags
        line("y"),
        line("recovery code"),
        line("y"), // hidden
        hidden(&format!("{REFUSED_HIDDEN}\u{7}")),
        hidden(HIDDEN_VALUE),
        line("n"),
        line("get github"),
        line("get github --show"),
        // passwd: wrong current master password
        line("passwd"),
        hidden(WRONG_CURRENT),
        hidden(NEW_MASTER),
        hidden(NEW_MASTER),
        // passwd: a weak new one
        line("passwd"),
        hidden(MASTER),
        hidden(WEAK_NEW),
        // passwd: success
        line("passwd"),
        hidden(MASTER),
        hidden(NEW_MASTER),
        hidden(NEW_MASTER),
        line(&format!("backup {}", backup.display())),
        line("log"),
        line("lock"),
    ];
    let (exit, t) = fx.run_on(&["unlock", "alice"], inputs, false);
    assert_eq!(exit, Exit::Success, "{}", t.stderr());
    assert_eq!(
        t.err,
        [
            "vault: wrong vaultname or master password",
            "vault: password: password must be 1-1024 characters, without control characters",
            "vault: custom field 1 value: custom field values must be 1-1024 characters, without control or formatting characters (hidden: 1-1024, without control characters)",
            "vault: hidden fields are only shown on a terminal, not into a pipe or file",
            "vault: wrong vaultname or master password",
            "vault: master password must be at least 12 characters",
        ]
    );
    for done in [
        "secret added",
        "recovery code: *",
        "master password changed",
        "Backup written to",
        "secret added 'github'",
    ] {
        assert!(
            t.stdout().contains(done),
            "{done:?} missing:\n{}",
            t.stdout()
        );
    }
    t
}

#[cfg(unix)]
#[test]
fn no_secret_reaches_output_diagnostics_or_the_audit_log() {
    use std::os::unix::fs::PermissionsExt;

    capture_diagnostics();
    let fx = Fixture::with_vault("alice", MASTER);
    // A loose vault file makes unlock log a diagnostic, showing the capture works.
    let vault_file = fx.dir.path().join("alice/secrets.vault");
    std::fs::set_permissions(&vault_file, std::fs::Permissions::from_mode(0o666)).unwrap();
    let elsewhere = tempfile::tempdir().unwrap();

    let init = init_carol(&fx);
    let session = alice_session(&fx, &elsewhere.path().join("alice.vault"));
    let (exit, again) = fx.run(&["unlock", "alice"], vec![hidden(NEW_MASTER), line("lock")]);
    assert_eq!(
        exit,
        Exit::Success,
        "the new master password opens the vault"
    );

    assert_terminal_clean("init", &init);
    assert_terminal_clean("the unlock session", &session);
    assert_terminal_clean("the unlock with the new master password", &again);

    let logs = String::from_utf8(LOGS.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("vault_file_permissions_loose"), "{logs}");
    assert_none_typed("diagnostics", &logs);

    for vaultname in ["alice", "carol"] {
        let audit_log = fx.dir.path().join(vaultname).join("audit.log");
        let audit_log = String::from_utf8_lossy(&std::fs::read(audit_log).unwrap()).into_owned();
        assert!(audit_log.contains("\"locked\""), "{audit_log}");
        assert_none_typed(&format!("{vaultname}'s audit.log"), &audit_log);
    }
}
