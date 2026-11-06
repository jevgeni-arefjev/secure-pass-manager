//! Behaviour of the session module, tested only through its public API.
//!
//! Every test gets its own temporary vault directory and a manual clock, so idle
//! timeouts and unlock delays are checked without sleeping. Vaults are created in the
//! test format (`create_insecure_for_tests`) so each Argon2id derivation stays fast.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::DateTime;
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::test_runner::TestRunner;
use tempfile::TempDir;
use vault_core::audit::{AuditError, AuditSink, Event, Line, MemorySink, Record};
use vault_core::crypto::{self, Header, MasterPassword, Plaintext};
use vault_core::session::{
    self, Clock, CustomField, CustomFieldPart, DEFAULT_IDLE_TIMEOUT, FieldProblem, FieldValue,
    HiddenValue, Saved, Secret, SecretField, Session, SessionConfig, SessionError,
    WeakMasterPassword,
};
use vault_core::storage::{FileStore, MAX_VAULT_FILE_LEN, VaultStore, Vaultname};

const PASSWORD: &str = "correct horse battery";

/// A clock that only moves when told to; sleeping moves it too, and is recorded.
struct ManualClock {
    start: Instant,
    elapsed: Mutex<Duration>,
    slept: Mutex<Duration>,
}

impl ManualClock {
    /// A clock at its starting point.
    ///
    /// ```text
    /// let clock = ManualClock::new();
    /// ```
    fn new() -> Arc<Self> {
        Arc::new(Self {
            start: Instant::now(),
            elapsed: Mutex::new(Duration::ZERO),
            slept: Mutex::new(Duration::ZERO),
        })
    }

    /// Moves time forward by `by`.
    ///
    /// ```text
    /// clock.advance(Duration::from_secs(60));
    /// ```
    fn advance(&self, by: Duration) {
        *self.elapsed.lock().unwrap() += by;
    }

    /// Total time spent in [`Clock::sleep`].
    ///
    /// ```text
    /// assert!(clock.slept() >= Duration::from_secs(1));
    /// ```
    fn slept(&self) -> Duration {
        *self.slept.lock().unwrap()
    }
}

impl Clock for ManualClock {
    /// The start instant plus however far time has been moved.
    ///
    /// ```text
    /// clock.now()
    /// ```
    fn now(&self) -> Instant {
        self.start + *self.elapsed.lock().unwrap()
    }

    /// A fixed date (2026-01-01) plus elapsed whole seconds.
    ///
    /// ```text
    /// clock.unix_time()
    /// ```
    fn unix_time(&self) -> u64 {
        1_767_225_600 + self.elapsed.lock().unwrap().as_secs()
    }

    /// Advances the clock instead of blocking, and records the sleep.
    ///
    /// ```text
    /// clock.sleep(Duration::from_secs(1));
    /// ```
    fn sleep(&self, duration: Duration) {
        *self.slept.lock().unwrap() += duration;
        self.advance(duration);
    }
}

/// A fresh vault directory, a manual clock and an in-memory audit log for one test.
struct Fixture {
    dir: TempDir,
    clock: Arc<ManualClock>,
    audit: Arc<MemorySink>,
}

impl Fixture {
    /// An empty vault directory and a clock at its start.
    ///
    /// ```text
    /// let fx = Fixture::new();
    /// ```
    fn new() -> Self {
        Self {
            dir: TempDir::new().unwrap(),
            clock: ManualClock::new(),
            audit: Arc::new(MemorySink::default()),
        }
    }

    /// A store on this fixture's vault directory.
    ///
    /// ```text
    /// let store = fx.store();
    /// ```
    fn store(&self) -> FileStore {
        FileStore::new(self.dir.path().join("vaults")).unwrap()
    }

    /// A config on this fixture's clock and audit log, with the default idle timeout.
    ///
    /// ```text
    /// Session::unlock(fx.store(), "alice", &pw, fx.config())
    /// ```
    fn config(&self) -> SessionConfig {
        SessionConfig {
            clock: self.clock.clone(),
            ..SessionConfig::new(self.audit.clone())
        }
    }

    /// The audit events recorded for `vaultname`, oldest first.
    ///
    /// ```text
    /// assert_eq!(fx.events("alice"), [Event::VaultCreated]);
    /// ```
    fn events(&self, vaultname: &str) -> Vec<Event> {
        self.records(vaultname)
            .into_iter()
            .map(|r| r.event)
            .collect()
    }

    /// The audit records for `vaultname`, oldest first.
    ///
    /// ```text
    /// let records = fx.records("alice");
    /// ```
    fn records(&self, vaultname: &str) -> Vec<Record> {
        let name = Vaultname::parse(vaultname).unwrap();
        let mut lines = self.audit.read_recent(&name, usize::MAX).unwrap();
        lines.reverse();
        lines
            .into_iter()
            .map(|line| match line {
                Line::Record(record) => record,
                Line::Unreadable => panic!("memory sink gave an unreadable line"),
            })
            .collect()
    }

    /// Creates vault `alice` under [`PASSWORD`] and returns its unlocked session.
    ///
    /// ```text
    /// let mut session = fx.create();
    /// ```
    fn create(&self) -> Session<FileStore> {
        self.try_create("alice", PASSWORD).unwrap()
    }

    /// Tries to create vault `vaultname` under `password`.
    ///
    /// ```text
    /// fx.try_create("alice", "short")
    /// ```
    fn try_create(
        &self,
        vaultname: &str,
        password: &str,
    ) -> Result<Session<FileStore>, SessionError> {
        Session::create_insecure_for_tests(
            self.store(),
            vaultname,
            &MasterPassword::new(password.into()),
            self.config(),
        )
    }

    /// Tries to unlock vault `vaultname` with `password`.
    ///
    /// ```text
    /// let mut session = fx.unlock("alice", PASSWORD).unwrap();
    /// ```
    fn unlock(&self, vaultname: &str, password: &str) -> Result<Session<FileStore>, SessionError> {
        Session::unlock(
            self.store(),
            vaultname,
            &MasterPassword::new(password.into()),
            self.config(),
        )
    }

    /// The raw bytes of `alice`'s vault file.
    ///
    /// ```text
    /// let bytes = fx.vault_file_bytes();
    /// ```
    fn vault_file_bytes(&self) -> Vec<u8> {
        std::fs::read(self.dir.path().join("vaults/alice/secrets.vault")).unwrap()
    }
}

/// A secret using every kind of field.
///
/// ```text
/// session.save(full_secret()).unwrap();
/// ```
fn full_secret() -> Secret {
    Secret::new("GitHub")
        .with_username("alice")
        .with_password(HiddenValue::new("p4ss-w0rd".into()))
        .with_url("https://github.com")
        .with_notes("2FA on\n\tbackup codes in the safe")
        .with_tag("work")
        .with_tag("dev")
        .with_custom_field(CustomField::plain("region", "eu-west"))
        .with_custom_field(CustomField::hidden(
            "recovery code",
            HiddenValue::new("1234-5678".into()),
        ))
}

/// The text of a custom field, revealing it if hidden.
///
/// ```text
/// assert_eq!(field_text(&secret.custom_fields()[0]), "eu-west");
/// ```
fn field_text(field: &CustomField) -> &str {
    match field.value() {
        FieldValue::Plain(text) => text,
        FieldValue::Hidden(hidden) => hidden.reveal(),
    }
}

/// What saving `secret` into a fresh vault gives.
///
/// ```text
/// assert_eq!(save_result(Secret::new("")), Err(...));
/// ```
fn save_result(secret: Secret) -> Result<Saved, SessionError> {
    Fixture::new().create().save(secret)
}

/// The problems of a refused save, `None` if it wasn't refused for its fields.
///
/// ```text
/// assert_eq!(problems(save_result(Secret::new(""))), Some(vec![FieldProblem::Title]));
/// ```
fn problems(result: Result<Saved, SessionError>) -> Option<Vec<FieldProblem>> {
    match result {
        Err(SessionError::InvalidSecret(invalid)) => Some(invalid.problems().to_vec()),
        _ => None,
    }
}

#[test]
fn every_field_survives_lock_and_unlock() {
    let fx = Fixture::new();
    let mut session = fx.create();
    assert_eq!(session.save(full_secret()), Ok(Saved::Added));
    session.lock();

    let mut session = fx.unlock("alice", PASSWORD).unwrap();
    let github = session.get("GitHub").unwrap();
    assert_eq!(github.title(), "GitHub");
    assert_eq!(github.username(), Some("alice"));
    assert_eq!(
        github.password().map(HiddenValue::reveal),
        Some("p4ss-w0rd")
    );
    assert_eq!(github.url(), Some("https://github.com"));
    assert_eq!(github.notes(), Some("2FA on\n\tbackup codes in the safe"));
    assert_eq!(github.tags().collect::<Vec<_>>(), ["work", "dev"]);
    let custom = github.custom_fields();
    assert_eq!(custom.len(), 2);
    assert_eq!(
        (custom[0].name(), custom[0].value().is_hidden()),
        ("region", false)
    );
    assert_eq!(field_text(&custom[0]), "eu-west");
    assert_eq!(
        (custom[1].name(), custom[1].value().is_hidden()),
        ("recovery code", true)
    );
    assert_eq!(field_text(&custom[1]), "1234-5678");
    assert_eq!(github.created_at(), fx.clock.unix_time());
}

#[test]
fn vault_file_never_contains_secrets_in_plaintext() {
    let fx = Fixture::new();
    fx.create().save(full_secret()).unwrap();
    let bytes = fx.vault_file_bytes();
    for needle in ["GitHub", "alice", "p4ss-w0rd", "1234-5678", "recovery code"] {
        assert!(
            !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
            "{needle} found in the vault file"
        );
    }
}

#[test]
fn unlock_with_wrong_password_fails_and_takes_at_least_a_second() {
    let fx = Fixture::new();
    fx.create().lock();
    assert_eq!(
        fx.unlock("alice", "wrong but long enough").err(),
        Some(SessionError::UnlockFailed)
    );
    assert!(fx.clock.slept() >= Duration::from_secs(1));
}

#[test]
fn unlock_of_missing_vault_fails_like_a_wrong_password() {
    let fx = Fixture::new();
    assert_eq!(
        fx.unlock("nobody", PASSWORD).err(),
        Some(SessionError::UnlockFailed)
    );
    assert!(fx.clock.slept() >= Duration::from_secs(1));
}

/// Overwrites `alice`'s vault file with each generated byte string and checks the
/// whole unlock path (storage, header decoder, KDF, key unwrap, body) refuses it with
/// one of the two errors a person may see, never a panic.
///
/// ```text
/// unlock_fails_for_every_file(&fx, 32, vec(any::<u8>(), 0..=8192));
/// ```
fn unlock_fails_for_every_file(fx: &Fixture, cases: u32, files: impl Strategy<Value = Vec<u8>>) {
    let path = fx.dir.path().join("vaults/alice/secrets.vault");
    TestRunner::new(ProptestConfig::with_cases(cases))
        .run(&files, |bytes| {
            std::fs::write(&path, &bytes).unwrap();
            let err = fx.unlock("alice", PASSWORD).err();
            prop_assert!(
                matches!(
                    err,
                    Some(SessionError::UnlockFailed | SessionError::VaultUnreadable)
                ),
                "{err:?}"
            );
            Ok(())
        })
        .unwrap();
}

/// Any file content in place of the vault file fails to unlock, without a panic.
#[test]
fn random_vault_files_never_unlock() {
    let fx = Fixture::new();
    fx.create().lock();
    unlock_fails_for_every_file(&fx, 256, vec(any::<u8>(), 0..=8192));
}

/// The real header with a random body reaches the key unwrap (which succeeds) and the
/// body tag check, so each case pays for one test-format derivation.
#[test]
fn real_header_with_a_random_body_never_unlocks() {
    let fx = Fixture::new();
    fx.create().lock();
    let header = fx.vault_file_bytes()[..Header::LEN].to_vec();
    let files = vec(any::<u8>(), 0..=8192).prop_map(move |body| [header.clone(), body].concat());
    unlock_fails_for_every_file(&fx, 32, files);
}

#[test]
fn successful_unlock_does_not_wait() {
    let fx = Fixture::new();
    fx.create().lock();
    fx.unlock("alice", PASSWORD).unwrap();
    assert_eq!(fx.clock.slept(), Duration::ZERO);
}

#[test]
fn vaultnames_are_validated_and_case_insensitive() {
    let fx = Fixture::new();
    assert_eq!(
        fx.try_create("../alice", PASSWORD).err(),
        Some(SessionError::InvalidVaultname)
    );
    assert_eq!(
        fx.unlock("../alice", PASSWORD).err(),
        Some(SessionError::InvalidVaultname)
    );
    fx.create().lock();
    let session = fx.unlock("ALICE", PASSWORD).unwrap();
    assert_eq!(session.vaultname().as_str(), "alice");
}

#[test]
fn a_vaultname_with_surrounding_spaces_opens_the_same_vault() {
    let fx = Fixture::new();
    fx.try_create(" alice ", PASSWORD).unwrap().lock();
    let session = fx.unlock("alice", PASSWORD).unwrap();
    assert_eq!(session.vaultname().as_str(), "alice");
    session.lock();
    assert!(fx.unlock("  alice", PASSWORD).is_ok());
}

#[test]
fn create_refuses_an_existing_vaultname() {
    let fx = Fixture::new();
    fx.create().lock();
    assert_eq!(
        fx.try_create("Alice", PASSWORD).err(),
        Some(SessionError::VaultExists)
    );
}

#[test]
fn weak_master_passwords_are_refused() {
    let fx = Fixture::new();
    let weak = |password| fx.try_create("alice", password).err();
    let too_short = Some(SessionError::WeakMasterPassword(
        WeakMasterPassword::TooShort,
    ));
    let too_common = Some(SessionError::WeakMasterPassword(
        WeakMasterPassword::TooCommon,
    ));
    assert_eq!(weak("elevenchars"), too_short);
    assert_eq!(weak("ääääääääää"), too_short); // 10 characters, 20 bytes
    assert_eq!(weak("Password1234"), too_common);
    assert_eq!(weak("aaaaaaaaaaaaaaaa"), too_common);
    assert!(fx.try_create("alice", "twelve chars").is_ok());
}

#[test]
fn a_new_master_password_must_be_at_most_1024_characters_after_nfc() {
    let fx = Fixture::new();
    let too_long = Some(SessionError::WeakMasterPassword(
        WeakMasterPassword::TooLong,
    ));
    assert!(fx.try_create("alice", &"ab".repeat(512)).is_ok());
    assert_eq!(
        fx.try_create("bob", &format!("{}c", "ab".repeat(512)))
            .err(),
        too_long
    );
    // 1024 decomposed "é" (e + combining acute, 2048 chars) NFC to 1024 characters.
    let decomposed = "e\u{301}".repeat(1023) + "x";
    assert!(fx.try_create("carol", &decomposed).is_ok());
    assert_eq!(
        SessionError::WeakMasterPassword(WeakMasterPassword::TooLong).to_string(),
        "master password must be at most 1024 characters"
    );
}

#[test]
fn a_new_master_password_must_not_hold_control_characters() {
    let fx = Fixture::new();
    let control = Some(SessionError::WeakMasterPassword(
        WeakMasterPassword::ControlCharacter,
    ));
    for password in [
        "correct\nhorse battery",
        "correct\thorse battery",
        "correct horse\u{1b}[0m",
        "correct horse\u{85}battery",
    ] {
        assert_eq!(fx.try_create("alice", password).err(), control);
    }
    assert_eq!(
        SessionError::WeakMasterPassword(WeakMasterPassword::ControlCharacter).to_string(),
        "master password must not contain control characters"
    );
}

#[test]
fn an_existing_master_password_breaking_the_new_rules_still_unlocks_and_can_be_changed() {
    let fx = Fixture::new();
    for (vaultname, old) in [("alice", "line one\nline two"), ("bob", &*"x1".repeat(600))] {
        // Written directly, as an older build without these rules could have.
        let old = MasterPassword::new(old.to_owned());
        let (_, sealed) = crypto::create_insecure_for_tests(
            &old,
            &Plaintext::new(br#"{"version":1,"secrets":[]}"#.to_vec()),
        )
        .unwrap();
        fx.store()
            .create(&Vaultname::parse(vaultname).unwrap(), &sealed)
            .unwrap();

        let mut session = Session::unlock(fx.store(), vaultname, &old, fx.config()).unwrap();
        session
            .change_master_password(&old, &MasterPassword::new("tr0ub4dor & 3 staples".into()))
            .unwrap();
        session.lock();
        assert!(fx.unlock(vaultname, "tr0ub4dor & 3 staples").is_ok());
    }
}

#[test]
fn a_failed_unlock_with_unusual_input_looks_like_any_other() {
    let fx = Fixture::new();
    fx.create().lock();
    for input in [
        "x".repeat(5000),
        "correct horse\nbattery".to_owned(),
        "\u{1b}[2J".to_owned(),
    ] {
        let slept_before = fx.clock.slept();
        assert_eq!(
            fx.unlock("alice", &input).err(),
            Some(SessionError::UnlockFailed)
        );
        assert!(fx.clock.slept() - slept_before >= Duration::from_secs(1));
    }
}

#[test]
fn master_password_is_unicode_normalized() {
    let fx = Fixture::new();
    // "é" decomposed (e + combining acute) at create, precomposed at unlock.
    fx.try_create("alice", "caf\u{65}\u{301} au lait!")
        .unwrap()
        .lock();
    assert!(fx.unlock("alice", "caf\u{e9} au lait!").is_ok());
}

#[test]
fn titles_match_ignoring_case_and_surrounding_spaces() {
    let fx = Fixture::new();
    let mut session = fx.create();
    session.save(Secret::new("  GitHub ")).unwrap();
    assert_eq!(session.get("github").unwrap().title(), "GitHub");
    assert_eq!(session.get(" GITHUB").unwrap().title(), "GitHub");
    assert!(session.contains("gItHuB").unwrap());
    assert_eq!(
        session.get("gitlab").err(),
        Some(SessionError::SecretNotFound)
    );
}

#[test]
fn saving_an_existing_title_replaces_the_whole_secret_and_keeps_created_at() {
    let fx = Fixture::new();
    let mut session = fx.create();
    session.save(full_secret()).unwrap();
    let created = session.get("github").unwrap().created_at();
    fx.clock.advance(Duration::from_secs(30));

    assert_eq!(
        session.save(Secret::new("github").with_username("bob")),
        Ok(Saved::Replaced)
    );
    let github = session.get("GitHub").unwrap();
    assert_eq!(github.title(), "github");
    assert_eq!(github.username(), Some("bob"));
    assert!(github.password().is_none());
    assert_eq!(github.created_at(), created);
    assert_eq!(github.updated_at(), created + 30);
    assert_eq!(session.list().unwrap().len(), 1);
}

#[test]
fn list_is_sorted_by_title_ignoring_case() {
    let fx = Fixture::new();
    let mut session = fx.create();
    for title in ["gitlab", "Amazon", "GitHub", "bank"] {
        session.save(Secret::new(title)).unwrap();
    }
    let titles: Vec<_> = session.list().unwrap().iter().map(|s| s.title()).collect();
    assert_eq!(titles, ["Amazon", "bank", "GitHub", "gitlab"]);
}

#[test]
fn removed_secrets_stay_removed_after_unlock() {
    let fx = Fixture::new();
    let mut session = fx.create();
    session.save(Secret::new("GitHub")).unwrap();
    session.save(Secret::new("gitlab")).unwrap();
    session.remove("GITHUB").unwrap();
    assert_eq!(session.remove("github"), Err(SessionError::SecretNotFound));
    session.lock();

    let mut session = fx.unlock("alice", PASSWORD).unwrap();
    let titles: Vec<_> = session.list().unwrap().iter().map(|s| s.title()).collect();
    assert_eq!(titles, ["gitlab"]);
}

#[test]
fn titles_and_fields_are_validated() {
    let invalid = |secret| problems(save_result(secret));
    let err = |problem| Some(vec![problem]);

    assert_eq!(invalid(Secret::new("   ")), err(FieldProblem::Title));
    assert_eq!(
        invalid(Secret::new("a".repeat(65))),
        err(FieldProblem::Title)
    );
    assert_eq!(
        invalid(Secret::new("git\u{1b}[2Jhub")),
        err(FieldProblem::Title)
    );
    assert_eq!(
        invalid(Secret::new("git\u{202e}buh")),
        err(FieldProblem::Title)
    );
    assert_eq!(
        invalid(Secret::new("git\u{200b}hub")),
        err(FieldProblem::Title)
    );
    assert_eq!(
        invalid(Secret::new("x").with_username("al\nice")),
        err(FieldProblem::Username)
    );
    assert_eq!(
        invalid(Secret::new("x").with_password(HiddenValue::new(String::new()))),
        err(FieldProblem::Password)
    );
    assert_eq!(
        invalid(Secret::new("x").with_password(HiddenValue::new("a".repeat(1025)))),
        err(FieldProblem::Password)
    );
    assert_eq!(
        invalid(Secret::new("x").with_url("https://x\u{7}")),
        err(FieldProblem::Url)
    );
    assert_eq!(
        invalid(Secret::new("x").with_notes("bell\u{7}")),
        err(FieldProblem::Notes)
    );
    assert_eq!(
        invalid(Secret::new("x").with_tag("work").with_tag("WORK")),
        err(FieldProblem::DuplicateTag(1))
    );
    assert_eq!(
        invalid((0..33).fold(Secret::new("x"), |s, i| s.with_tag(format!("t{i}")))),
        err(FieldProblem::TooManyTags)
    );
    assert_eq!(
        invalid(Secret::new("x").with_custom_field(CustomField::plain("Password", "y"))),
        err(FieldProblem::DuplicateCustomFieldName(0))
    );
    assert_eq!(
        invalid(
            Secret::new("x")
                .with_custom_field(CustomField::plain("pin", "1"))
                .with_custom_field(CustomField::plain("PIN", "2"))
        ),
        err(FieldProblem::DuplicateCustomFieldName(1))
    );
    assert_eq!(
        invalid(Secret::new("x").with_custom_field(CustomField::plain("pin", ""))),
        err(FieldProblem::CustomFieldValue(0))
    );
}

#[test]
fn every_invalid_field_is_reported_at_once() {
    let secret = Secret::new("   ")
        .with_url("https://x\u{7}")
        .with_tag("work")
        .with_tag("")
        .with_tag("WORK")
        .with_custom_field(CustomField::plain("region", "r".repeat(1025)))
        .with_custom_field(CustomField::plain("", ""))
        .with_custom_field(CustomField::plain("REGION", "eu"));

    let found = problems(save_result(secret)).unwrap();
    assert_eq!(
        found,
        [
            FieldProblem::Title,
            FieldProblem::Url,
            FieldProblem::Tag(1),
            FieldProblem::DuplicateTag(2),
            FieldProblem::CustomFieldValue(0),
            FieldProblem::CustomFieldName(1),
            FieldProblem::CustomFieldValue(1),
            FieldProblem::DuplicateCustomFieldName(2),
        ]
    );
    let located: Vec<_> = found
        .iter()
        .map(|problem| (problem.field(), problem.index(), problem.part()))
        .collect();
    assert_eq!(
        located,
        [
            (SecretField::Title, None, None),
            (SecretField::Url, None, None),
            (SecretField::Tags, Some(1), None),
            (SecretField::Tags, Some(2), None),
            (
                SecretField::CustomFields,
                Some(0),
                Some(CustomFieldPart::Value)
            ),
            (
                SecretField::CustomFields,
                Some(1),
                Some(CustomFieldPart::Name)
            ),
            (
                SecretField::CustomFields,
                Some(1),
                Some(CustomFieldPart::Value)
            ),
            (
                SecretField::CustomFields,
                Some(2),
                Some(CustomFieldPart::Name)
            ),
        ]
    );
}

#[test]
fn too_many_tags_and_custom_fields_are_reported_with_the_others() {
    let secret = (0..33)
        .fold(Secret::new("x"), |s, i| s.with_tag(format!("t{i}")))
        .with_tag("")
        .with_username("");
    let secret = (0..33).fold(secret, |s, i| {
        s.with_custom_field(CustomField::plain(format!("f{i}"), "v"))
    });
    assert_eq!(
        problems(save_result(secret)).unwrap(),
        [
            FieldProblem::Username,
            FieldProblem::TooManyTags,
            FieldProblem::Tag(33),
            FieldProblem::TooManyCustomFields,
        ]
    );
}

#[test]
fn problem_messages_state_the_rule_and_never_the_value() {
    let secret = Secret::new("zebracorn\u{1b}")
        .with_password(HiddenValue::new("zebracorn\u{7}".to_owned()))
        .with_tag("zebracorn\u{7}")
        .with_custom_field(CustomField::hidden(
            "zebracorn\u{7}",
            HiddenValue::new("zebracorn\u{7}".to_owned()),
        ));
    let Err(SessionError::InvalidSecret(invalid)) = save_result(secret) else {
        panic!("expected a refused secret");
    };
    assert_eq!(invalid.problems().len(), 5);
    assert_eq!(
        invalid.problems()[0].to_string(),
        "title must be 1-64 characters, without control characters"
    );
    for problem in invalid.problems() {
        assert!(!problem.to_string().contains("zebracorn"), "{problem}");
    }
    assert!(!invalid.to_string().contains("zebracorn"));
    assert!(!format!("{invalid:?}").contains("zebracorn"));
}

#[test]
fn boundary_values_are_accepted() {
    let secret = Secret::new("é".repeat(64))
        .with_username("u".repeat(256))
        .with_password(HiddenValue::new("p".repeat(1024)))
        .with_url("h".repeat(2048))
        .with_notes(format!("line one\n\tline two{}", "n".repeat(4000)))
        .with_tag("t".repeat(32));
    assert_eq!(save_result(secret), Ok(Saved::Added));
}

#[test]
fn invalid_secret_changes_nothing() {
    let fx = Fixture::new();
    let mut session = fx.create();
    session
        .save(Secret::new("GitHub").with_username("alice"))
        .unwrap();
    assert!(
        session
            .save(Secret::new("github").with_username("\u{1b}"))
            .is_err()
    );
    assert_eq!(session.get("github").unwrap().username(), Some("alice"));
}

#[test]
fn session_auto_locks_after_idle_timeout() {
    let fx = Fixture::new();
    let mut session = fx.create();
    session.save(Secret::new("GitHub")).unwrap();

    fx.clock.advance(Duration::from_secs(4 * 60));
    assert!(session.contains("github").unwrap()); // activity resets the timer
    fx.clock.advance(Duration::from_secs(4 * 60));
    assert!(session.is_unlocked());

    fx.clock.advance(Duration::from_secs(60));
    assert!(!session.is_unlocked());
    assert_eq!(session.get("github").err(), Some(SessionError::Locked));
    assert_eq!(session.save(Secret::new("x")), Err(SessionError::Locked));
    assert_eq!(session.list().err(), Some(SessionError::Locked));
}

#[test]
fn checking_lock_state_is_not_activity() {
    let fx = Fixture::new();
    let mut session = fx.create();
    fx.clock.advance(Duration::from_secs(4 * 60));
    assert!(session.is_unlocked());
    fx.clock.advance(Duration::from_secs(60));
    assert!(!session.is_unlocked());
}

#[test]
fn idle_timeout_is_configurable() {
    let fx = Fixture::new();
    fx.create().lock();
    let config = SessionConfig {
        idle_timeout: Duration::from_secs(10),
        ..fx.config()
    };
    let password = MasterPassword::new(PASSWORD.into());
    let mut session = Session::unlock(fx.store(), "alice", &password, config).unwrap();
    fx.clock.advance(Duration::from_secs(10));
    assert!(!session.is_unlocked());
}

#[test]
fn concurrent_save_conflicts_and_locks_the_stale_session() {
    let fx = Fixture::new();
    fx.create().lock();
    let mut first = fx.unlock("alice", PASSWORD).unwrap();
    let mut second = fx.unlock("alice", PASSWORD).unwrap();

    first.save(Secret::new("GitHub")).unwrap();
    assert_eq!(
        second.save(Secret::new("gitlab")),
        Err(SessionError::Conflict)
    );
    assert!(!second.is_unlocked());

    let mut fresh = fx.unlock("alice", PASSWORD).unwrap();
    let titles: Vec<_> = fresh.list().unwrap().iter().map(|s| s.title()).collect();
    assert_eq!(titles, ["GitHub"]);
}

#[test]
fn failed_write_leaves_secrets_unchanged() {
    let fx = Fixture::new();
    let mut session = fx.create();
    session.save(Secret::new("GitHub")).unwrap();
    std::fs::remove_file(fx.dir.path().join("vaults/alice/secrets.vault")).unwrap();

    assert_eq!(
        session.save(Secret::new("gitlab")),
        Err(SessionError::Storage)
    );
    assert_eq!(session.remove("github"), Err(SessionError::Storage));
    assert!(session.is_unlocked());
    let titles: Vec<_> = session.list().unwrap().iter().map(|s| s.title()).collect();
    assert_eq!(titles, ["GitHub"]);
}

#[test]
fn changing_the_master_password_keeps_secrets_and_retires_the_old_one() {
    let fx = Fixture::new();
    let mut session = fx.create();
    session.save(full_secret()).unwrap();
    let new = "tr0ub4dor & 3 staples";
    session
        .change_master_password(
            &MasterPassword::new(PASSWORD.into()),
            &MasterPassword::new(new.into()),
        )
        .unwrap();
    // The session keeps working with the rotated vault key.
    session.save(Secret::new("gitlab")).unwrap();
    session.lock();

    assert_eq!(
        fx.unlock("alice", PASSWORD).err(),
        Some(SessionError::UnlockFailed)
    );
    let mut session = fx.unlock("alice", new).unwrap();
    assert_eq!(session.list().unwrap().len(), 2);
    let github = session.get("github").unwrap();
    assert_eq!(
        github.password().map(HiddenValue::reveal),
        Some("p4ss-w0rd")
    );
}

#[test]
fn changing_the_master_password_needs_the_current_one_and_a_strong_new_one() {
    let fx = Fixture::new();
    let mut session = fx.create();
    let strong = MasterPassword::new("tr0ub4dor & 3 staples".into());

    assert_eq!(
        session.change_master_password(&MasterPassword::new("not the password".into()), &strong),
        Err(SessionError::UnlockFailed)
    );
    assert!(fx.clock.slept() >= Duration::from_secs(1));
    assert!(session.is_unlocked());

    assert_eq!(
        session.change_master_password(
            &MasterPassword::new(PASSWORD.into()),
            &MasterPassword::new("short".into())
        ),
        Err(SessionError::WeakMasterPassword(
            WeakMasterPassword::TooShort
        ))
    );
    session.lock();
    assert!(fx.unlock("alice", PASSWORD).is_ok());
}

#[test]
fn a_save_past_the_vault_size_limit_is_refused_and_changes_nothing() {
    let fx = Fixture::new();
    fx.create().lock();
    session::fill_vault_for_tests(&fx.store(), "alice", &MasterPassword::new(PASSWORD.into()))
        .unwrap();
    let before = fx.vault_file_bytes();
    assert!(before.len() as u64 <= MAX_VAULT_FILE_LEN);
    assert!(before.len() as u64 > MAX_VAULT_FILE_LEN - 4096);
    let mut session = fx.unlock("alice", PASSWORD).unwrap();

    assert_eq!(
        session.save(Secret::new("one more")),
        Err(SessionError::VaultFull)
    );
    assert_eq!(SessionError::VaultFull.to_string(), "vault is full");
    assert!(session.is_unlocked());
    assert_eq!(
        session.get("one more").err(),
        Some(SessionError::SecretNotFound)
    );
    assert_eq!(fx.vault_file_bytes(), before);

    // Removing a secret still works, so a full vault can always be made smaller.
    session.remove(session::FILLER_TITLE).unwrap();
    session.save(Secret::new("one more")).unwrap();
    session.lock();
    let mut session = fx.unlock("alice", PASSWORD).unwrap();
    assert_eq!(session.list().unwrap().len(), 1);
}

#[test]
fn error_messages_carry_no_secret_input() {
    let fx = Fixture::new();
    let mut session = fx.create();
    let err = session
        .save(Secret::new("x").with_password(HiddenValue::new("bad\u{7}secret".into())))
        .unwrap_err();
    let message = err.to_string();
    assert!(!message.contains("bad") && !message.contains("secret\u{7}"));
    assert!(!format!("{err:?}").contains("bad"));
}

#[test]
fn sessions_can_move_between_threads() {
    /// Compiles only if `T` is `Send`, as the web server will need for its sessions.
    ///
    /// ```text
    /// assert_send::<Session<FileStore>>();
    /// ```
    fn assert_send<T: Send>() {}
    assert_send::<Session<FileStore>>();
}

// ---- Audit events (ADR-0010) ----

/// `Event::SecretAdded` for the secret `title`.
///
/// ```text
/// assert_eq!(fx.events("alice")[1], added("GitHub"));
/// ```
fn added(title: &str) -> Event {
    Event::SecretAdded {
        title: title.to_owned(),
    }
}

/// `Event::SecretReplaced` for the secret `title`.
///
/// ```text
/// assert_eq!(fx.events("alice")[2], replaced("github"));
/// ```
fn replaced(title: &str) -> Event {
    Event::SecretReplaced {
        title: title.to_owned(),
    }
}

/// `Event::SecretRemoved` for the secret `title`.
///
/// ```text
/// assert_eq!(fx.events("alice")[3], removed("github"));
/// ```
fn removed(title: &str) -> Event {
    Event::SecretRemoved {
        title: title.to_owned(),
    }
}

/// `Event::SecretRevealed` for the secret `title`.
///
/// ```text
/// assert_eq!(fx.events("alice").last(), Some(&revealed("GitHub")));
/// ```
fn revealed(title: &str) -> Event {
    Event::SecretRevealed {
        title: title.to_owned(),
    }
}

/// A sink whose every write and read fails, like a full disk.
struct FailingSink;

impl AuditSink for FailingSink {
    /// Always fails.
    ///
    /// ```text
    /// assert!(FailingSink.append(&alice, &record).is_err());
    /// ```
    fn append(&self, _: &Vaultname, _: &Record) -> Result<(), AuditError> {
        Err(AuditError)
    }

    /// Always fails.
    ///
    /// ```text
    /// assert!(FailingSink.read_recent(&alice, 20).is_err());
    /// ```
    fn read_recent(&self, _: &Vaultname, _: usize) -> Result<Vec<Line>, AuditError> {
        Err(AuditError)
    }
}

#[test]
fn create_unlock_and_lock_are_recorded_with_the_clock_time_in_utc() {
    let fx = Fixture::new();
    fx.create().lock();
    fx.clock.advance(Duration::from_secs(60));
    fx.unlock("alice", PASSWORD).unwrap().lock();

    let records = fx.records("alice");
    let events: Vec<_> = records.iter().map(|r| r.event.clone()).collect();
    assert_eq!(
        events,
        [
            Event::VaultCreated,
            Event::Locked,
            Event::Unlocked,
            Event::Locked
        ]
    );
    assert_eq!(
        records[0].time,
        DateTime::from_timestamp(1_767_225_600, 0).unwrap()
    );
    assert_eq!(
        records[2].time,
        DateTime::from_timestamp(1_767_225_660, 0).unwrap()
    );
}

#[test]
fn failed_unlock_is_recorded_before_the_minimum_delay_runs_out() {
    let fx = Fixture::new();
    fx.create().lock();
    let started = fx.clock.unix_time();

    assert_eq!(
        fx.unlock("alice", "wrong guess").err(),
        Some(SessionError::UnlockFailed)
    );

    let failure = fx.records("alice").pop().unwrap();
    assert_eq!(failure.event, Event::UnlockFailed);
    assert_eq!(failure.time.timestamp(), i64::try_from(started).unwrap());
    assert!(fx.clock.slept() >= Duration::from_secs(1));
}

#[test]
fn failed_unlock_of_an_unknown_vaultname_records_nothing() {
    let fx = Fixture::new();
    assert!(fx.unlock("bob", PASSWORD).is_err());
    assert_eq!(fx.events("bob"), []);
    assert!(!fx.dir.path().join("vaults/bob").exists());
}

#[test]
fn saved_and_removed_secrets_are_recorded_with_their_title() {
    let fx = Fixture::new();
    let mut session = fx.create();
    session.save(Secret::new("GitHub")).unwrap();
    session.save(Secret::new("github")).unwrap();
    session.remove("GITHUB").unwrap();

    assert_eq!(
        fx.events("alice")[1..],
        [added("GitHub"), replaced("github"), removed("github"),]
    );
}

#[test]
fn listing_masked_get_and_failed_changes_record_nothing() {
    let fx = Fixture::new();
    let mut session = fx.create();
    session.save(full_secret()).unwrap();
    let before = fx.events("alice");

    session.list().unwrap();
    session.get("github").unwrap();
    session.contains("github").unwrap();
    assert!(session.remove("nothing").is_err());
    assert!(session.save(Secret::new("")).is_err());

    assert_eq!(fx.events("alice"), before);
}

#[test]
fn reveal_is_recorded_only_when_the_front_end_succeeds() {
    let fx = Fixture::new();
    let mut session = fx.create();
    session.save(full_secret()).unwrap();

    let password = session
        .reveal("github", |secret| {
            Ok::<_, SessionError>(secret.password().unwrap().reveal().to_owned())
        })
        .unwrap();
    assert_eq!(password, "p4ss-w0rd");
    let failed: Result<(), SessionError> = session.reveal("github", |_| Err(SessionError::Storage));
    assert_eq!(failed, Err(SessionError::Storage));
    let missing: Result<(), SessionError> = session.reveal("nothing", |_| Ok(()));
    assert_eq!(missing, Err(SessionError::SecretNotFound));

    assert_eq!(fx.events("alice").last(), Some(&revealed("GitHub")));
    assert_eq!(
        fx.events("alice")
            .iter()
            .filter(|e| matches!(e, Event::SecretRevealed { .. }))
            .count(),
        1
    );
}

#[test]
fn auto_lock_conflict_and_signal_locks_are_recorded() {
    let fx = Fixture::new();
    let mut idle = fx.create();
    fx.clock.advance(DEFAULT_IDLE_TIMEOUT);
    assert!(!idle.is_unlocked());
    idle.lock();

    let mut first = fx.unlock("alice", PASSWORD).unwrap();
    let mut second = fx.unlock("alice", PASSWORD).unwrap();
    first.save(Secret::new("GitHub")).unwrap();
    assert!(second.save(Secret::new("gitlab")).is_err());
    first.lock_on_signal();

    assert_eq!(
        fx.events("alice"),
        [
            Event::VaultCreated,
            Event::AutoLocked,
            Event::Unlocked,
            Event::Unlocked,
            added("GitHub"),
            Event::LockedOnConflict,
            Event::TerminatedBySignal,
        ]
    );
}

#[test]
fn master_password_changes_are_recorded_whether_they_succeed_or_not() {
    let fx = Fixture::new();
    let mut session = fx.create();
    let new = MasterPassword::new("tr0ub4dor & 3 staples".into());
    let wrong = MasterPassword::new("wrong guess".into());

    assert!(session.change_master_password(&wrong, &new).is_err());
    session
        .change_master_password(&MasterPassword::new(PASSWORD.into()), &new)
        .unwrap();

    assert_eq!(
        fx.events("alice")[1..],
        [
            Event::MasterPasswordChangeFailed,
            Event::MasterPasswordChanged
        ]
    );
}

#[test]
fn a_failing_audit_log_never_blocks_the_operation() {
    let fx = Fixture::new();
    let config = || SessionConfig {
        clock: fx.clock.clone(),
        ..SessionConfig::new(Arc::new(FailingSink))
    };
    let password = MasterPassword::new(PASSWORD.into());
    let mut session =
        Session::create_insecure_for_tests(fx.store(), "alice", &password, config()).unwrap();
    session.save(full_secret()).unwrap();
    session
        .reveal("github", |_| Ok::<_, SessionError>(()))
        .unwrap();
    session.remove("github").unwrap();
    session.lock();

    assert!(Session::unlock(fx.store(), "alice", &password, config()).is_ok());
}

#[test]
fn audit_log_gives_this_vaults_events_newest_first() {
    let fx = Fixture::new();
    fx.try_create("bob", PASSWORD).unwrap().lock();
    let mut session = fx.create();
    session.save(Secret::new("GitHub")).unwrap();

    let lines = session.audit_log(20).unwrap();
    let events: Vec<_> = lines
        .into_iter()
        .map(|line| match line {
            Line::Record(record) => record.event,
            Line::Unreadable => panic!("unexpected unreadable line"),
        })
        .collect();
    assert_eq!(events, [added("GitHub"), Event::VaultCreated]);
    assert_eq!(session.audit_log(1).unwrap().len(), 1);
}

#[test]
fn audit_log_is_refused_once_locked() {
    let fx = Fixture::new();
    let mut session = fx.create();
    fx.clock.advance(DEFAULT_IDLE_TIMEOUT);
    assert_eq!(session.audit_log(20).err(), Some(SessionError::Locked));
}

#[test]
fn audit_log_that_cannot_be_read_is_an_error() {
    let fx = Fixture::new();
    let config = SessionConfig {
        clock: fx.clock.clone(),
        ..SessionConfig::new(Arc::new(FailingSink))
    };
    let password = MasterPassword::new(PASSWORD.into());
    let mut session =
        Session::create_insecure_for_tests(fx.store(), "alice", &password, config).unwrap();
    assert_eq!(session.audit_log(20).err(), Some(SessionError::AuditLog));
}
