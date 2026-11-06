//! Behaviour of the backup module and `Session::backup`, tested only through the public
//! API.
//!
//! Every test gets its own vault directory and a separate directory to back up into.
//! Vaults are created in the test format (`create_insecure_for_tests`) so each Argon2id
//! derivation stays fast.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tempfile::TempDir;
use vault_core::audit::{AuditSink, Event, Line, MemorySink};
use vault_core::backup::{BackupError, Destination};
use vault_core::crypto::{MasterPassword, SealedVault};
use vault_core::session::{Secret, Session, SessionConfig, SessionError};
use vault_core::storage::{FileStore, StorageError, VaultStore, Vaultname};

const PASSWORD: &str = "correct horse battery";

/// A vault directory, a directory outside it to back up into, and an in-memory audit
/// log for one test.
struct Fixture {
    vaults: TempDir,
    elsewhere: TempDir,
    audit: Arc<MemorySink>,
}

impl Fixture {
    /// Empty directories and an empty audit log.
    ///
    /// ```text
    /// let fx = Fixture::new();
    /// ```
    fn new() -> Self {
        Self {
            vaults: TempDir::new().unwrap(),
            elsewhere: TempDir::new().unwrap(),
            audit: Arc::new(MemorySink::default()),
        }
    }

    /// A store on this fixture's vault directory.
    ///
    /// ```text
    /// let store = fx.store();
    /// ```
    fn store(&self) -> FileStore {
        FileStore::new(self.vaults.path()).unwrap()
    }

    /// A config recording to this fixture's audit log.
    ///
    /// ```text
    /// Session::unlock(fx.store(), "alice", &pw, fx.config())
    /// ```
    fn config(&self) -> SessionConfig {
        SessionConfig::new(self.audit.clone())
    }

    /// Creates vault `alice` under [`PASSWORD`] on `store` and returns it unlocked.
    ///
    /// ```text
    /// let mut session = fx.create_on(fx.store());
    /// ```
    fn create_on<S: VaultStore>(&self, store: S) -> Session<S> {
        Session::create_insecure_for_tests(store, "alice", &password(PASSWORD), self.config())
            .unwrap()
    }

    /// Creates vault `alice` under [`PASSWORD`] and returns it unlocked.
    ///
    /// ```text
    /// let mut session = fx.create();
    /// ```
    fn create(&self) -> Session<FileStore> {
        self.create_on(self.store())
    }

    /// Unlocks vault `vaultname` with `typed`.
    ///
    /// ```text
    /// let session = fx.unlock("alice", PASSWORD)?;
    /// ```
    fn unlock(&self, vaultname: &str, typed: &str) -> Result<Session<FileStore>, SessionError> {
        Session::unlock(self.store(), vaultname, &password(typed), self.config())
    }

    /// A path named `name` in the directory outside the vault directory.
    ///
    /// ```text
    /// let path = fx.outside("alice.vault");
    /// ```
    fn outside(&self, name: &str) -> PathBuf {
        self.elsewhere.path().join(name)
    }

    /// `path` checked as a backup destination for this fixture's vault directory.
    ///
    /// ```text
    /// let dest = fx.dest(&fx.outside("alice.vault")).unwrap();
    /// ```
    fn dest(&self, path: &Path) -> Result<Destination, BackupError> {
        Destination::new(path, self.vaults.path())
    }

    /// The audit events recorded for `alice`, oldest first.
    ///
    /// ```text
    /// assert_eq!(fx.events().last(), Some(&Event::BackupCreated { revision: 0 }));
    /// ```
    fn events(&self) -> Vec<Event> {
        let name = Vaultname::parse("alice").unwrap();
        let mut lines = self.audit.read_recent(&name, usize::MAX).unwrap();
        lines.reverse();
        lines
            .into_iter()
            .map(|line| match line {
                Line::Record(record) => record.event,
                Line::Unreadable => panic!("memory sink gave an unreadable line"),
            })
            .collect()
    }

    /// Names of the entries in the directory outside the vault directory, sorted.
    ///
    /// ```text
    /// assert_eq!(fx.outside_entries(), ["alice.vault"]);
    /// ```
    fn outside_entries(&self) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(self.elsewhere.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }
}

/// A master password from `typed`.
///
/// ```text
/// let pw = password(PASSWORD);
/// ```
fn password(typed: &str) -> MasterPassword {
    MasterPassword::new(typed.into())
}

/// A file store that, once armed, hands out the stored vault with one body byte
/// flipped: the header still matches the session, but the body no longer opens.
struct CorruptingStore {
    inner: FileStore,
    armed: Arc<AtomicBool>,
}

impl VaultStore for CorruptingStore {
    fn create(&self, name: &Vaultname, sealed: &SealedVault) -> Result<(), StorageError> {
        self.inner.create(name, sealed)
    }

    fn load(&self, name: &Vaultname) -> Result<SealedVault, StorageError> {
        let mut sealed = self.inner.load(name)?;
        if self.armed.load(Ordering::SeqCst) {
            sealed.body[0] ^= 1;
        }
        Ok(sealed)
    }

    fn save(&self, name: &Vaultname, sealed: &SealedVault) -> Result<(), StorageError> {
        self.inner.save(name, sealed)
    }
}

// --- destination rules ----------------------------------------------------------------

#[test]
fn a_free_name_in_an_existing_directory_outside_the_vault_directory_is_accepted() {
    let fx = Fixture::new();
    assert!(fx.dest(&fx.outside("alice.vault")).is_ok());
}

#[test]
fn an_existing_file_is_refused() {
    let fx = Fixture::new();
    fs::write(fx.outside("taken"), b"keep me").unwrap();
    assert_eq!(
        fx.dest(&fx.outside("taken")).err(),
        Some(BackupError::Exists)
    );
}

#[test]
fn an_existing_directory_is_refused() {
    let fx = Fixture::new();
    fs::create_dir(fx.outside("dir")).unwrap();
    assert_eq!(fx.dest(&fx.outside("dir")).err(), Some(BackupError::Exists));
}

#[cfg(unix)]
#[test]
fn a_symlink_is_refused_even_when_it_dangles() {
    let fx = Fixture::new();
    std::os::unix::fs::symlink(fx.outside("nowhere"), fx.outside("link")).unwrap();
    assert_eq!(
        fx.dest(&fx.outside("link")).err(),
        Some(BackupError::Exists)
    );
}

#[test]
fn a_missing_directory_is_refused_and_not_created() {
    let fx = Fixture::new();
    let path = fx.outside("missing/alice.vault");
    assert_eq!(fx.dest(&path).err(), Some(BackupError::NoDirectory));
    assert!(!fx.outside("missing").exists());
}

#[test]
fn a_file_as_the_directory_is_refused() {
    let fx = Fixture::new();
    fs::write(fx.outside("file"), b"").unwrap();
    assert_eq!(
        fx.dest(&fx.outside("file/alice.vault")).err(),
        Some(BackupError::NoDirectory)
    );
}

#[test]
fn paths_inside_the_vault_directory_are_refused() {
    let fx = Fixture::new();
    fx.create().lock();
    for path in [
        fx.vaults.path().join("alice.vault"),
        fx.vaults.path().join("alice/backup.vault"),
        fx.vaults.path().join("alice/../x.vault"),
    ] {
        assert_eq!(
            fx.dest(&path).err(),
            Some(BackupError::InsideVaultDirectory),
            "{path:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_symlinked_directory_into_the_vault_directory_is_refused() {
    let fx = Fixture::new();
    std::os::unix::fs::symlink(fx.vaults.path(), fx.outside("sneaky")).unwrap();
    assert_eq!(
        fx.dest(&fx.outside("sneaky/alice.vault")).err(),
        Some(BackupError::InsideVaultDirectory)
    );
}

#[test]
fn paths_that_do_not_name_a_file_are_refused() {
    let fx = Fixture::new();
    let trailing_slash = format!("{}/", fx.outside("dir").display());
    for path in [
        PathBuf::new(),
        PathBuf::from("/"),
        fx.outside(".."),
        PathBuf::from(trailing_slash),
    ] {
        assert_eq!(
            fx.dest(&path).err(),
            Some(BackupError::NotAFilePath),
            "{path:?}"
        );
    }
}

#[test]
fn error_messages_never_carry_the_path() {
    let fx = Fixture::new();
    let path = fx.outside("missing/alice.vault");
    let message = fx.dest(&path).unwrap_err().to_string();
    assert!(!message.contains("missing"), "{message}");
}

// --- Session::backup ------------------------------------------------------------------

#[test]
fn backup_is_the_stored_vault_file_byte_for_byte() {
    let fx = Fixture::new();
    let mut session = fx.create();
    session.save(Secret::new("GitHub")).unwrap();
    let path = fx.outside("alice.vault");

    assert_eq!(session.backup(&fx.dest(&path).unwrap()), Ok(1));
    assert_eq!(
        fs::read(&path).unwrap(),
        fs::read(fx.vaults.path().join("alice/secrets.vault")).unwrap()
    );
}

#[test]
fn backup_leaves_no_temp_file_behind() {
    let fx = Fixture::new();
    let mut session = fx.create();
    session
        .backup(&fx.dest(&fx.outside("alice.vault")).unwrap())
        .unwrap();
    assert_eq!(fx.outside_entries(), ["alice.vault"]);
}

#[cfg(unix)]
#[test]
fn backup_is_readable_only_by_its_owner() {
    use std::os::unix::fs::PermissionsExt;
    let fx = Fixture::new();
    let path = fx.outside("alice.vault");
    fx.create().backup(&fx.dest(&path).unwrap()).unwrap();
    let mode = fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn backup_is_recorded_with_its_revision_and_without_its_path() {
    let fx = Fixture::new();
    let mut session = fx.create();
    session.save(Secret::new("GitHub")).unwrap();
    session.save(Secret::new("gitlab")).unwrap();
    session
        .backup(&fx.dest(&fx.outside("alice.vault")).unwrap())
        .unwrap();
    assert_eq!(
        fx.events().last(),
        Some(&Event::BackupCreated { revision: 2 })
    );
}

#[test]
fn a_file_created_after_the_check_is_never_overwritten() {
    let fx = Fixture::new();
    let mut session = fx.create();
    let path = fx.outside("alice.vault");
    let dest = fx.dest(&path).unwrap();
    fs::write(&path, b"keep me").unwrap();

    assert_eq!(
        session.backup(&dest),
        Err(SessionError::Backup(BackupError::Exists))
    );
    assert_eq!(fs::read(&path).unwrap(), b"keep me");
    assert_eq!(fx.outside_entries(), ["alice.vault"]);
    assert!(!fx.events().contains(&Event::BackupCreated { revision: 0 }));
    assert!(session.is_unlocked());
}

#[test]
fn a_backup_that_does_not_verify_is_never_put_in_place() {
    let fx = Fixture::new();
    let armed = Arc::new(AtomicBool::new(false));
    let mut session = fx.create_on(CorruptingStore {
        inner: fx.store(),
        armed: Arc::clone(&armed),
    });
    let dest = fx.dest(&fx.outside("alice.vault")).unwrap();
    armed.store(true, Ordering::SeqCst);

    assert_eq!(
        session.backup(&dest),
        Err(SessionError::Backup(BackupError::Unverified))
    );
    assert!(fx.outside_entries().is_empty());
    assert!(!fx.events().contains(&Event::BackupCreated { revision: 0 }));
    assert!(session.is_unlocked());
}

#[test]
fn a_vault_saved_by_another_session_locks_this_one_like_a_save_conflict() {
    let fx = Fixture::new();
    fx.create().lock();
    let mut first = fx.unlock("alice", PASSWORD).unwrap();
    let mut second = fx.unlock("alice", PASSWORD).unwrap();
    first.save(Secret::new("GitHub")).unwrap();

    let path = fx.outside("alice.vault");
    assert_eq!(
        second.backup(&fx.dest(&path).unwrap()),
        Err(SessionError::Conflict)
    );
    assert!(!second.is_unlocked());
    assert!(fx.outside_entries().is_empty());
    assert_eq!(fx.events().last(), Some(&Event::LockedOnConflict));
}

#[test]
fn a_locked_session_makes_no_backup() {
    let fx = Fixture::new();
    fx.create().lock();
    let mut first = fx.unlock("alice", PASSWORD).unwrap();
    let mut second = fx.unlock("alice", PASSWORD).unwrap();
    first.save(Secret::new("GitHub")).unwrap();
    let _ = second.save(Secret::new("gitlab")); // conflict: `second` locks

    let dest = fx.dest(&fx.outside("alice.vault")).unwrap();
    assert_eq!(second.backup(&dest), Err(SessionError::Locked));
    assert!(fx.outside_entries().is_empty());
}

#[test]
fn a_backup_restored_under_another_vaultname_unlocks_with_the_same_secrets() {
    let fx = Fixture::new();
    let mut session = fx.create();
    session
        .save(Secret::new("GitHub").with_username("alice"))
        .unwrap();
    let path = fx.outside("alice.vault");
    session.backup(&fx.dest(&path).unwrap()).unwrap();
    session.lock();

    // The manual restore: a new vault home with the backup as `secrets.vault`.
    let home = fx.vaults.path().join("bob");
    fs::create_dir(&home).unwrap();
    fs::copy(&path, home.join("secrets.vault")).unwrap();

    let mut restored = fx.unlock("bob", PASSWORD).unwrap();
    assert_eq!(restored.get("github").unwrap().username(), Some("alice"));
}

#[test]
fn a_backup_after_passwd_opens_with_the_new_master_password_only() {
    let fx = Fixture::new();
    let mut session = fx.create();
    let new = "tr0ub4dor & 3 staples";
    session
        .change_master_password(&password(PASSWORD), &password(new))
        .unwrap();
    let path = fx.outside("alice.vault");
    session.backup(&fx.dest(&path).unwrap()).unwrap();

    let home = fx.vaults.path().join("restored");
    fs::create_dir(&home).unwrap();
    fs::copy(&path, home.join("secrets.vault")).unwrap();
    assert_eq!(
        fx.unlock("restored", PASSWORD).err(),
        Some(SessionError::UnlockFailed)
    );
    assert!(fx.unlock("restored", new).is_ok());
}

// --- Session::backup_file -------------------------------------------------------------

#[test]
fn backup_file_is_the_stored_vault_file_byte_for_byte_with_its_revision() {
    let fx = Fixture::new();
    let mut session = fx.create();
    session.save(Secret::new("GitHub")).unwrap();

    let file = session.backup_file().unwrap();
    assert_eq!(file.revision(), 1);
    assert_eq!(
        file.bytes(),
        fs::read(fx.vaults.path().join("alice/secrets.vault")).unwrap()
    );
    assert_eq!(
        fx.events().last(),
        Some(&Event::BackupCreated { revision: 1 })
    );
}

#[test]
fn backup_file_that_does_not_open_with_the_vault_key_is_refused() {
    let fx = Fixture::new();
    let armed = Arc::new(AtomicBool::new(false));
    let mut session = fx.create_on(CorruptingStore {
        inner: fx.store(),
        armed: Arc::clone(&armed),
    });
    armed.store(true, Ordering::SeqCst);

    assert_eq!(
        session.backup_file().err(),
        Some(SessionError::Backup(BackupError::Unverified))
    );
    assert!(!fx.events().contains(&Event::BackupCreated { revision: 0 }));
    assert!(session.is_unlocked());
}

#[test]
fn backup_file_of_a_vault_saved_by_another_session_locks_this_one() {
    let fx = Fixture::new();
    fx.create().lock();
    let mut first = fx.unlock("alice", PASSWORD).unwrap();
    let mut second = fx.unlock("alice", PASSWORD).unwrap();
    first.save(Secret::new("GitHub")).unwrap();

    assert_eq!(second.backup_file().err(), Some(SessionError::Conflict));
    assert!(!second.is_unlocked());
    assert_eq!(fx.events().last(), Some(&Event::LockedOnConflict));
}

#[test]
fn backup_file_restored_by_hand_unlocks_with_the_same_secrets() {
    let fx = Fixture::new();
    let mut session = fx.create();
    session
        .save(Secret::new("GitHub").with_username("alice"))
        .unwrap();
    let file = session.backup_file().unwrap();
    session.lock();

    let home = fx.vaults.path().join("bob");
    fs::create_dir(&home).unwrap();
    fs::write(home.join("secrets.vault"), file.bytes()).unwrap();

    let mut restored = fx.unlock("bob", PASSWORD).unwrap();
    assert_eq!(restored.get("github").unwrap().username(), Some("alice"));
}
