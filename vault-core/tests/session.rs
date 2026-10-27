//! Behaviour of the session module, tested only through its public API.
//!
//! Every test gets its own temporary vault directory and a manual clock, so idle
//! timeouts and unlock delays are checked without sleeping. Vaults are created in the
//! test format (`create_insecure_for_tests`) so each Argon2id derivation stays fast.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::DateTime;
use tempfile::TempDir;
use vault_core::audit::{AuditError, AuditSink, Event, Line, MemorySink, Record};
use vault_core::crypto::MasterPassword;
use vault_core::session::{
    Clock, CustomField, DEFAULT_IDLE_TIMEOUT, FieldValue, HiddenValue, InvalidSecret, Saved,
    Secret, Session, SessionConfig, SessionError, WeakMasterPassword,
};
use vault_core::storage::{SqliteStore, Vaultname};

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
    fn store(&self) -> SqliteStore {
        SqliteStore::new(self.dir.path().join("vaults")).unwrap()
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
    fn create(&self) -> Session<SqliteStore> {
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
    ) -> Result<Session<SqliteStore>, SessionError> {
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
    fn unlock(
        &self,
        vaultname: &str,
        password: &str,
    ) -> Result<Session<SqliteStore>, SessionError> {
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
    let invalid = |secret| save_result(secret).err();
    let err = |e| Some(SessionError::InvalidSecret(e));

    assert_eq!(invalid(Secret::new("   ")), err(InvalidSecret::Title));
    assert_eq!(
        invalid(Secret::new("a".repeat(65))),
        err(InvalidSecret::Title)
    );
    assert_eq!(
        invalid(Secret::new("git\u{1b}[2Jhub")),
        err(InvalidSecret::Title)
    );
    assert_eq!(
        invalid(Secret::new("git\u{202e}buh")),
        err(InvalidSecret::Title)
    );
    assert_eq!(
        invalid(Secret::new("git\u{200b}hub")),
        err(InvalidSecret::Title)
    );
    assert_eq!(
        invalid(Secret::new("x").with_username("al\nice")),
        err(InvalidSecret::Username)
    );
    assert_eq!(
        invalid(Secret::new("x").with_password(HiddenValue::new(String::new()))),
        err(InvalidSecret::Password)
    );
    assert_eq!(
        invalid(Secret::new("x").with_password(HiddenValue::new("a".repeat(1025)))),
        err(InvalidSecret::Password)
    );
    assert_eq!(
        invalid(Secret::new("x").with_url("https://x\u{7}")),
        err(InvalidSecret::Url)
    );
    assert_eq!(
        invalid(Secret::new("x").with_notes("bell\u{7}")),
        err(InvalidSecret::Notes)
    );
    assert_eq!(
        invalid(Secret::new("x").with_tag("work").with_tag("WORK")),
        err(InvalidSecret::DuplicateTag)
    );
    assert_eq!(
        invalid((0..33).fold(Secret::new("x"), |s, i| s.with_tag(format!("t{i}")))),
        err(InvalidSecret::TooManyTags)
    );
    assert_eq!(
        invalid(Secret::new("x").with_custom_field(CustomField::plain("Password", "y"))),
        err(InvalidSecret::DuplicateCustomFieldName)
    );
    assert_eq!(
        invalid(
            Secret::new("x")
                .with_custom_field(CustomField::plain("pin", "1"))
                .with_custom_field(CustomField::plain("PIN", "2"))
        ),
        err(InvalidSecret::DuplicateCustomFieldName)
    );
    assert_eq!(
        invalid(Secret::new("x").with_custom_field(CustomField::plain("pin", ""))),
        err(InvalidSecret::CustomFieldValue)
    );
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
    /// assert_send::<Session<SqliteStore>>();
    /// ```
    fn assert_send<T: Send>() {}
    assert_send::<Session<SqliteStore>>();
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
