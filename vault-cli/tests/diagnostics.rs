//! Diagnostics as the person sees them on stderr: each event code as one sentence
//! (ADR-0014), through `diagnostics::sentence`, the real `vault` binary and the panic
//! hook.

use vault_cli::diagnostics;

#[test]
fn each_event_code_is_one_sentence() {
    let cases = [
        (
            "audit_write_failed",
            "vault: warning: the audit log of vault 'alice' could not be written; this session's events are not recorded",
        ),
        (
            "audit_log_permissions_loose",
            "vault: warning: the audit log of vault 'alice' is writable by other users; run `chmod go-w` on it",
        ),
        (
            "memory_lock_unavailable",
            "vault: warning: memory for vault 'alice' could not be locked; its secrets may be written to swap",
        ),
        (
            "vault_directory_permissions_loose",
            "vault: warning: the vault directory is writable by other users; run `chmod go-w` on it",
        ),
        (
            "vault_home_permissions_loose",
            "vault: warning: the vault home of vault 'alice' is writable by other users; run `chmod go-w` on it",
        ),
        (
            "vault_file_permissions_loose",
            "vault: warning: the vault file of vault 'alice' is writable by other users; run `chmod go-w` on it",
        ),
        (
            "vault_temp_cleanup_failed",
            "vault: warning: a temporary file left by an earlier save could not be removed",
        ),
        (
            "vault_directory_sync_failed",
            "vault: warning: the last save could not be flushed to disk; it may be lost if the system crashes",
        ),
        (
            "signal_handlers_unavailable",
            "vault: warning: termination signals can't be caught; if this process is killed, the clipboard is not cleared",
        ),
    ];
    for (code, sentence) in cases {
        assert_eq!(
            diagnostics::sentence(code, Some("alice")).as_deref(),
            Some(sentence),
            "{code}"
        );
    }
}

#[test]
fn the_vaultname_is_named_only_for_the_vaults_own_files() {
    assert_eq!(
        diagnostics::sentence("vault_directory_sync_failed", Some("alice")).as_deref(),
        Some(
            "vault: warning: the last save could not be flushed to disk; it may be lost if the system crashes"
        )
    );
    assert_eq!(
        diagnostics::sentence("vault_file_permissions_loose", None).as_deref(),
        Some("vault: warning: the vault file is writable by other users; run `chmod go-w` on it")
    );
}

#[test]
fn an_unknown_code_is_printed_as_the_bare_code() {
    assert_eq!(
        diagnostics::sentence("something_new", Some("alice")).as_deref(),
        Some("vault: warning: something_new")
    );
}

#[test]
fn an_internal_error_is_not_printed_again() {
    // The CLI already shows the error itself: `vault: vault storage failed (disk full)`.
    assert_eq!(diagnostics::sentence("internal_error", None), None);
}

#[cfg(unix)]
#[test]
fn the_binary_prints_a_loose_vault_file_as_a_sentence() {
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};
    use std::sync::Arc;

    use vault_core::audit::FileSink;
    use vault_core::crypto::MasterPassword;
    use vault_core::session::{Session, SessionConfig};
    use vault_core::storage::FileStore;

    let dir = tempfile::tempdir().unwrap();
    let password = MasterPassword::new("correct horse battery".to_owned());
    let config = SessionConfig::new(Arc::new(FileSink::new(dir.path())));
    Session::create_insecure_for_tests(
        FileStore::new(dir.path()).unwrap(),
        "alice",
        &password,
        config,
    )
    .unwrap()
    .lock();
    let file = dir.path().join("alice/secrets.vault");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();

    // `init` of a taken vaultname loads the vault file before any prompt.
    let output = Command::new(env!("CARGO_BIN_EXE_vault"))
        .arg("--vault-dir")
        .arg(dir.path())
        .args(["init", "alice"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert_eq!(
        stderr.lines().next(),
        Some(
            "vault: warning: the vault file of vault 'alice' is writable by other users; run `chmod go-w` on it"
        ),
        "{stderr}"
    );
    assert!(!stderr.contains("event="), "{stderr}");
}

/// Set in the child process of [`a_panic_prints_only_its_location`].
const PANIC_CHILD: &str = "VAULT_TEST_PANIC_CHILD";

#[test]
fn a_panic_prints_only_its_location() {
    if std::env::var_os(PANIC_CHILD).is_some() {
        diagnostics::print_panics_without_message();
        panic!("s3cret! in a panic message");
    }
    // The hook is process-wide, so it is installed in a child run of this test only.
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "a_panic_prints_only_its_location", "--nocapture"])
        .env(PANIC_CHILD, "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(!output.status.success());
    assert!(
        !stderr.contains("s3cret!") && !stdout.contains("s3cret!"),
        "{stderr}"
    );
    let line = stderr
        .lines()
        .find(|line| line.starts_with("vault: internal error at "))
        .unwrap_or_else(|| panic!("no location line: {stderr}"));
    let location = line.trim_start_matches("vault: internal error at ");
    let (file, number) = location.rsplit_once(':').unwrap();
    assert!(file.ends_with("tests/diagnostics.rs"), "{line}");
    assert!(number.parse::<u32>().is_ok(), "{line}");
}
