//! Session module: unlocks one vault (vaultname + master password), holds its decrypted
//! secrets for the session, reveals them one at a time, and wipes them on lock or auto-lock.
//!
//! Owns the secret model and its JSON serialization. A session only ever sees the vault it
//! unlocked, so no per-secret ownership checks are needed (ADR-0001).
//!
//! Security:
//! - A [`Session`] exists only while its vault is unlocked. [`Session::lock`] consumes it;
//!   auto-lock (idle timeout) and a save conflict wipe the keys and secrets in place, and
//!   every later call returns [`SessionError::Locked`].
//! - Every failed unlock looks the same: a missing vault costs the same Argon2id run as
//!   a wrong master password ([`crypto::simulate_unlock`]), and every failure takes at
//!   least one second, so vaultnames can't be probed.
//! - Every change is sealed and saved at once; nothing unsaved lives only in memory.
//! - Hidden values are page-locked; if any key, body or hidden value can't be locked, one
//!   `memory_lock_unavailable` warning is logged per session.
//! - Audit events go to `tracing` with the vaultname only, never a title or field.
//!
//! ```
//! use vault_core::crypto::MasterPassword;
//! use vault_core::session::{HiddenValue, Secret, Session, SessionConfig};
//! use vault_core::storage::SqliteStore;
//!
//! let dir = tempfile::tempdir()?;
//! let password = MasterPassword::new("correct horse battery".into());
//! let mut session = Session::create_insecure_for_tests(
//!     SqliteStore::new(dir.path())?, "alice", &password, SessionConfig::default(),
//! )?;
//! session.save(Secret::new("GitHub").with_password(HiddenValue::new("s3cret!".into())))?;
//! session.lock();
//!
//! let mut session =
//!     Session::unlock(SqliteStore::new(dir.path())?, "alice", &password, SessionConfig::default())?;
//! let github = session.get("github")?;
//! assert_eq!(github.password().map(HiddenValue::reveal), Some("s3cret!"));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod body;
mod clock;
mod master_password_policy;
mod secret;

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::crypto::{self, CryptoError, Header, MasterPassword, Plaintext, SealedVault, VaultKey};
use crate::storage::{StorageError, VaultStore, Vaultname};

pub use clock::{Clock, SystemClock};
pub use master_password_policy::{MIN_MASTER_PASSWORD_CHARS, WeakMasterPassword};
pub use secret::{CustomField, FieldValue, HiddenValue, InvalidSecret, Secret};

/// Idle time after which a session locks itself, unless configured otherwise.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Shortest time any failed unlock takes, so failures can't be told apart by timing.
const MIN_UNLOCK_FAILURE: Duration = Duration::from_secs(1);

/// How a session behaves; front ends start from [`SessionConfig::default`].
///
/// ```
/// use std::time::Duration;
/// use vault_core::session::SessionConfig;
///
/// let config = SessionConfig {
///     idle_timeout: Duration::from_secs(60),
///     ..SessionConfig::default()
/// };
/// ```
pub struct SessionConfig {
    /// Idle time after which the session locks itself.
    pub idle_timeout: Duration,
    /// Where time comes from; [`SystemClock`] outside tests.
    pub clock: Arc<dyn Clock>,
}

impl Default for SessionConfig {
    /// A 5-minute idle timeout on the system clock.
    ///
    /// ```
    /// # use vault_core::session::{SessionConfig, DEFAULT_IDLE_TIMEOUT};
    /// assert_eq!(SessionConfig::default().idle_timeout, DEFAULT_IDLE_TIMEOUT);
    /// ```
    fn default() -> Self {
        Self {
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            clock: Arc::new(SystemClock),
        }
    }
}

/// Why a session operation failed. Messages are fixed strings: they never carry a
/// password, title or field value.
///
/// ```
/// use vault_core::session::SessionError;
/// assert_eq!(SessionError::UnlockFailed.to_string(), "wrong vaultname or master password");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionError {
    /// No vault with this vaultname, a wrong master password, or a tampered header.
    /// Deliberately indistinguishable.
    UnlockFailed,
    /// The vaultname breaks the allowlist (see [`Vaultname`]).
    InvalidVaultname,
    /// `create` was asked for a vaultname that already has a vault.
    VaultExists,
    /// A new master password is too weak.
    WeakMasterPassword(WeakMasterPassword),
    /// The session has locked (idle timeout or a save conflict); unlock again.
    Locked,
    /// Another session saved this vault first. This session is now locked; unlock
    /// again to see the current secrets.
    Conflict,
    /// No secret with this title.
    SecretNotFound,
    /// A secret breaks the field rules.
    InvalidSecret(InvalidSecret),
    /// The vault file, its header or its body isn't something this build can read.
    VaultUnreadable,
    /// The file system or database failed.
    Storage,
    /// The OS random number generator failed.
    Randomness,
}

impl fmt::Display for SessionError {
    /// Writes the fixed message for this error.
    ///
    /// ```
    /// # use vault_core::session::SessionError;
    /// assert_eq!(SessionError::Locked.to_string(), "vault is locked");
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnlockFailed => f.write_str("wrong vaultname or master password"),
            Self::InvalidVaultname => StorageError::InvalidVaultname.fmt(f),
            Self::VaultExists => StorageError::AlreadyExists.fmt(f),
            Self::WeakMasterPassword(weak) => weak.fmt(f),
            Self::Locked => f.write_str("vault is locked"),
            Self::Conflict => f.write_str(
                "vault was changed by another session; it is now locked, unlock it again",
            ),
            Self::SecretNotFound => f.write_str("no secret with this title"),
            Self::InvalidSecret(invalid) => invalid.fmt(f),
            Self::VaultUnreadable => f.write_str("vault file can't be read"),
            Self::Storage => StorageError::Io.fmt(f),
            Self::Randomness => CryptoError::Randomness.fmt(f),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<StorageError> for SessionError {
    /// Maps a storage failure; `NotFound` outside unlock means the file vanished.
    ///
    /// ```
    /// # use vault_core::{session::SessionError, storage::StorageError};
    /// assert_eq!(SessionError::from(StorageError::Conflict), SessionError::Conflict);
    /// ```
    fn from(err: StorageError) -> Self {
        match err {
            StorageError::InvalidVaultname => Self::InvalidVaultname,
            StorageError::AlreadyExists => Self::VaultExists,
            StorageError::Conflict => Self::Conflict,
            StorageError::NotAVault => Self::VaultUnreadable,
            StorageError::NotFound | StorageError::Io => Self::Storage,
        }
    }
}

impl From<CryptoError> for SessionError {
    /// Maps a crypto failure.
    ///
    /// ```
    /// # use vault_core::{crypto::CryptoError, session::SessionError};
    /// assert_eq!(SessionError::from(CryptoError::BodyCorrupt), SessionError::VaultUnreadable);
    /// ```
    fn from(err: CryptoError) -> Self {
        match err {
            CryptoError::UnlockFailed => Self::UnlockFailed,
            CryptoError::BodyCorrupt | CryptoError::UnsupportedFormat => Self::VaultUnreadable,
            CryptoError::Randomness => Self::Randomness,
        }
    }
}

impl From<WeakMasterPassword> for SessionError {
    /// Wraps a master password policy failure.
    ///
    /// ```
    /// # use vault_core::session::{SessionError, WeakMasterPassword};
    /// let err = SessionError::from(WeakMasterPassword::TooShort);
    /// ```
    fn from(err: WeakMasterPassword) -> Self {
        Self::WeakMasterPassword(err)
    }
}

impl From<InvalidSecret> for SessionError {
    /// Wraps a field rule failure.
    ///
    /// ```
    /// # use vault_core::session::{InvalidSecret, SessionError};
    /// let err = SessionError::from(InvalidSecret::Title);
    /// ```
    fn from(err: InvalidSecret) -> Self {
        Self::InvalidSecret(err)
    }
}

/// What [`Session::save`] did.
///
/// ```
/// use vault_core::session::Saved;
/// assert_ne!(Saved::Added, Saved::Replaced);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Saved {
    /// No secret had this title; it was added.
    Added,
    /// A secret with this title (ignoring case) was replaced as a whole.
    Replaced,
}

/// One unlocked vault: its vault key, current header and decrypted secrets.
///
/// Security: one session reaches only the vaultname it was unlocked with (ADR-0001).
/// Dropping it, [`Session::lock`], auto-lock or a conflict wipes everything it holds.
///
/// ```
/// # use vault_core::crypto::MasterPassword;
/// # use vault_core::session::{Session, SessionConfig};
/// # use vault_core::storage::SqliteStore;
/// # let dir = tempfile::tempdir()?;
/// # let store = SqliteStore::new(dir.path())?;
/// let password = MasterPassword::new("correct horse battery".into());
/// let session =
///     Session::create_insecure_for_tests(store, "alice", &password, SessionConfig::default())?;
/// session.lock();
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct Session<S: VaultStore> {
    store: S,
    vaultname: Vaultname,
    config: SessionConfig,
    /// `None` once auto-locked or locked by a conflict.
    open: Option<OpenVault>,
    last_used: Instant,
    warned_memory_unlocked: bool,
}

/// What an unlocked session holds.
struct OpenVault {
    key: VaultKey,
    header: Header,
    secrets: Vec<Secret>,
}

/// How to put the secrets back after a change that couldn't be saved.
enum Undo {
    /// Remove the secret that was added at the end.
    Pop,
    /// Put back the secret that was replaced at this index.
    Restore(usize, Secret),
    /// Put back the secret that was removed from this index.
    Insert(usize, Secret),
}

/// Creates a new sealed vault from a master password and a body (production or test format).
type SealNew = fn(&MasterPassword, &Plaintext) -> Result<(VaultKey, SealedVault), CryptoError>;

impl<S: VaultStore> Session<S> {
    /// Creates an empty vault named `vaultname` under `password` and returns it unlocked.
    ///
    /// Security: refuses a weak master password ([`WeakMasterPassword`]) and an existing
    /// vaultname ([`SessionError::VaultExists`]); costs one 256 MiB Argon2id run.
    ///
    /// ```no_run
    /// # use vault_core::crypto::MasterPassword;
    /// # use vault_core::session::{Session, SessionConfig};
    /// # use vault_core::storage::SqliteStore;
    /// let store = SqliteStore::new("/home/alice/.local/share/secure-pass-manager/vaults")?;
    /// let password = MasterPassword::new("correct horse battery".into());
    /// let session = Session::create(store, "alice", &password, SessionConfig::default())?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn create(
        store: S,
        vaultname: &str,
        password: &MasterPassword,
        config: SessionConfig,
    ) -> Result<Self, SessionError> {
        Self::create_with(store, vaultname, password, config, crypto::create)
    }

    /// Like [`Session::create`], but in the test format (cheap KDF, ADR-0005).
    ///
    /// Security: never for real vaults. Exists only with the `insecure-test-kdf`
    /// feature, which release builds refuse.
    ///
    /// ```
    /// # use vault_core::crypto::MasterPassword;
    /// # use vault_core::session::{Session, SessionConfig};
    /// # use vault_core::storage::SqliteStore;
    /// # let dir = tempfile::tempdir()?;
    /// let password = MasterPassword::new("correct horse battery".into());
    /// let session = Session::create_insecure_for_tests(
    ///     SqliteStore::new(dir.path())?, "alice", &password, SessionConfig::default(),
    /// )?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[cfg(feature = "insecure-test-kdf")]
    pub fn create_insecure_for_tests(
        store: S,
        vaultname: &str,
        password: &MasterPassword,
        config: SessionConfig,
    ) -> Result<Self, SessionError> {
        Self::create_with(
            store,
            vaultname,
            password,
            config,
            crypto::create_insecure_for_tests,
        )
    }

    /// Shared body of the create functions: validates, seals an empty body with
    /// `seal_new`, stores it and opens the session.
    ///
    /// ```ignore
    /// Self::create_with(store, "alice", &password, config, crypto::create)
    /// ```
    fn create_with(
        store: S,
        vaultname: &str,
        password: &MasterPassword,
        config: SessionConfig,
        seal_new: SealNew,
    ) -> Result<Self, SessionError> {
        let vaultname = Vaultname::parse(vaultname)?;
        master_password_policy::check(password)?;
        let secrets = Vec::new();
        let plaintext = body::encode(&secrets);
        let (key, sealed) = seal_new(password, &plaintext)?;
        store.create(&vaultname, &sealed)?;
        tracing::info!(event = "vault_created", vaultname = %vaultname);
        let vault = OpenVault {
            key,
            header: sealed.header,
            secrets,
        };
        Ok(Self::opened(store, vaultname, config, vault, &plaintext))
    }

    /// Unlocks the vault named `vaultname` with `password`.
    ///
    /// Security: a missing vault, a wrong master password and a tampered header all
    /// give [`SessionError::UnlockFailed`] after the same Argon2id cost and at least one
    /// second. The failure is logged with the vaultname only if that vault exists, so a
    /// password typed into the vaultname prompt by mistake doesn't end up in the log.
    ///
    /// ```
    /// # use vault_core::crypto::MasterPassword;
    /// # use vault_core::session::{Session, SessionConfig, SessionError};
    /// # use vault_core::storage::SqliteStore;
    /// # let dir = tempfile::tempdir()?;
    /// # let password = MasterPassword::new("correct horse battery".into());
    /// # Session::create_insecure_for_tests(SqliteStore::new(dir.path())?, "alice", &password, SessionConfig::default())?;
    /// let wrong = MasterPassword::new("wrong guess".into());
    /// let result = Session::unlock(SqliteStore::new(dir.path())?, "alice", &wrong, SessionConfig::default());
    /// assert_eq!(result.err(), Some(SessionError::UnlockFailed));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn unlock(
        store: S,
        vaultname: &str,
        password: &MasterPassword,
        config: SessionConfig,
    ) -> Result<Self, SessionError> {
        let vaultname = Vaultname::parse(vaultname)?;
        let started = config.clock.now();
        match open_vault(&store, &vaultname, password) {
            Ok((vault, plaintext)) => {
                tracing::info!(event = "unlocked", vaultname = %vaultname);
                Ok(Self::opened(store, vaultname, config, vault, &plaintext))
            }
            Err(err) => {
                wait_out_failure(config.clock.as_ref(), started);
                Err(err)
            }
        }
    }

    /// Wraps an opened vault into a session and checks its memory is locked.
    ///
    /// ```ignore
    /// Ok(Self::opened(store, vaultname, config, vault, &plaintext))
    /// ```
    fn opened(
        store: S,
        vaultname: Vaultname,
        config: SessionConfig,
        vault: OpenVault,
        plaintext: &Plaintext,
    ) -> Self {
        let last_used = config.clock.now();
        let mut session = Self {
            store,
            vaultname,
            config,
            open: Some(vault),
            last_used,
            warned_memory_unlocked: false,
        };
        session.check_memory_locked(plaintext.is_memory_locked());
        session
    }

    /// The vaultname this session unlocked.
    ///
    /// ```
    /// # use vault_core::crypto::MasterPassword;
    /// # use vault_core::session::{Session, SessionConfig};
    /// # use vault_core::storage::SqliteStore;
    /// # let dir = tempfile::tempdir()?;
    /// # let password = MasterPassword::new("correct horse battery".into());
    /// let session = Session::create_insecure_for_tests(
    ///     SqliteStore::new(dir.path())?, "Alice", &password, SessionConfig::default(),
    /// )?;
    /// assert_eq!(session.vaultname().as_str(), "alice");
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn vaultname(&self) -> &Vaultname {
        &self.vaultname
    }

    /// Whether the session is still unlocked. Auto-locks first if the idle timeout has
    /// passed; checking doesn't count as activity.
    ///
    /// ```
    /// # use vault_core::crypto::MasterPassword;
    /// # use vault_core::session::{Session, SessionConfig};
    /// # use vault_core::storage::SqliteStore;
    /// # let dir = tempfile::tempdir()?;
    /// # let password = MasterPassword::new("correct horse battery".into());
    /// # let mut session = Session::create_insecure_for_tests(SqliteStore::new(dir.path())?, "alice", &password, SessionConfig::default())?;
    /// assert!(session.is_unlocked());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn is_unlocked(&mut self) -> bool {
        self.lock_if_idle(self.config.clock.now());
        self.open.is_some()
    }

    /// The secret titled `title` (ignoring case and surrounding spaces). Hidden fields
    /// stay masked until [`HiddenValue::reveal`] is called on one.
    ///
    /// ```
    /// # use vault_core::crypto::MasterPassword;
    /// # use vault_core::session::{Secret, Session, SessionConfig};
    /// # use vault_core::storage::SqliteStore;
    /// # let dir = tempfile::tempdir()?;
    /// # let password = MasterPassword::new("correct horse battery".into());
    /// # let mut session = Session::create_insecure_for_tests(SqliteStore::new(dir.path())?, "alice", &password, SessionConfig::default())?;
    /// session.save(Secret::new("GitHub").with_username("alice"))?;
    /// assert_eq!(session.get("github")?.username(), Some("alice"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn get(&mut self, title: &str) -> Result<&Secret, SessionError> {
        self.vault()?
            .secrets
            .iter()
            .find(|secret| secret.has_title(title))
            .ok_or(SessionError::SecretNotFound)
    }

    /// Whether a secret titled `title` exists (ignoring case), e.g. to ask before
    /// overwriting it.
    ///
    /// ```
    /// # use vault_core::crypto::MasterPassword;
    /// # use vault_core::session::{Session, SessionConfig};
    /// # use vault_core::storage::SqliteStore;
    /// # let dir = tempfile::tempdir()?;
    /// # let password = MasterPassword::new("correct horse battery".into());
    /// # let mut session = Session::create_insecure_for_tests(SqliteStore::new(dir.path())?, "alice", &password, SessionConfig::default())?;
    /// assert!(!session.contains("github")?);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn contains(&mut self, title: &str) -> Result<bool, SessionError> {
        Ok(self
            .vault()?
            .secrets
            .iter()
            .any(|secret| secret.has_title(title)))
    }

    /// All secrets, sorted by title ignoring case. Front ends show only the
    /// non-hidden fields.
    ///
    /// ```
    /// # use vault_core::crypto::MasterPassword;
    /// # use vault_core::session::{Secret, Session, SessionConfig};
    /// # use vault_core::storage::SqliteStore;
    /// # let dir = tempfile::tempdir()?;
    /// # let password = MasterPassword::new("correct horse battery".into());
    /// # let mut session = Session::create_insecure_for_tests(SqliteStore::new(dir.path())?, "alice", &password, SessionConfig::default())?;
    /// session.save(Secret::new("gitlab"))?;
    /// session.save(Secret::new("GitHub"))?;
    /// let titles: Vec<_> = session.list()?.iter().map(|s| s.title()).collect();
    /// assert_eq!(titles, ["GitHub", "gitlab"]);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn list(&mut self) -> Result<Vec<&Secret>, SessionError> {
        let mut secrets: Vec<_> = self.vault()?.secrets.iter().collect();
        secrets.sort_by(|a, b| a.cmp_title(b));
        Ok(secrets)
    }

    /// Saves `secret`, replacing as a whole any secret with the same title (ignoring
    /// case), and writes the vault at once.
    ///
    /// Security: the secret is validated first ([`InvalidSecret`]); on a storage
    /// conflict the session locks ([`SessionError::Conflict`]); on any other failure
    /// nothing changes.
    ///
    /// ```
    /// # use vault_core::crypto::MasterPassword;
    /// # use vault_core::session::{HiddenValue, Saved, Secret, Session, SessionConfig};
    /// # use vault_core::storage::SqliteStore;
    /// # let dir = tempfile::tempdir()?;
    /// # let password = MasterPassword::new("correct horse battery".into());
    /// # let mut session = Session::create_insecure_for_tests(SqliteStore::new(dir.path())?, "alice", &password, SessionConfig::default())?;
    /// let github = Secret::new("GitHub").with_password(HiddenValue::new("s3cret!".into()));
    /// assert_eq!(session.save(github)?, Saved::Added);
    /// assert_eq!(session.save(Secret::new("github"))?, Saved::Replaced);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn save(&mut self, mut secret: Secret) -> Result<Saved, SessionError> {
        let now = self.config.clock.unix_time();
        let vault = self.vault()?;
        secret.validate()?;
        let existing = vault
            .secrets
            .iter()
            .position(|stored| stored.has_title(secret.title()));
        secret.stamp(existing.map(|i| vault.secrets[i].created_at()), now);
        let (saved, undo) = match existing {
            Some(i) => (
                Saved::Replaced,
                Undo::Restore(i, std::mem::replace(&mut vault.secrets[i], secret)),
            ),
            None => {
                vault.secrets.push(secret);
                (Saved::Added, Undo::Pop)
            }
        };
        self.persist(undo)?;
        tracing::info!(event = "secret_saved", vaultname = %self.vaultname);
        Ok(saved)
    }

    /// Removes the secret titled `title` (ignoring case) and writes the vault at once.
    ///
    /// ```
    /// # use vault_core::crypto::MasterPassword;
    /// # use vault_core::session::{Secret, Session, SessionConfig, SessionError};
    /// # use vault_core::storage::SqliteStore;
    /// # let dir = tempfile::tempdir()?;
    /// # let password = MasterPassword::new("correct horse battery".into());
    /// # let mut session = Session::create_insecure_for_tests(SqliteStore::new(dir.path())?, "alice", &password, SessionConfig::default())?;
    /// session.save(Secret::new("GitHub"))?;
    /// session.remove("github")?;
    /// assert_eq!(session.remove("github"), Err(SessionError::SecretNotFound));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn remove(&mut self, title: &str) -> Result<(), SessionError> {
        let vault = self.vault()?;
        let i = vault
            .secrets
            .iter()
            .position(|secret| secret.has_title(title))
            .ok_or(SessionError::SecretNotFound)?;
        let removed = vault.secrets.remove(i);
        self.persist(Undo::Insert(i, removed))?;
        tracing::info!(event = "secret_removed", vaultname = %self.vaultname);
        Ok(())
    }

    /// Changes the master password. `current` is checked first; the vault key is rotated
    /// and the vault rewritten at once.
    ///
    /// Security: a wrong `current` gives [`SessionError::UnlockFailed`] after at least
    /// one second, and the session stays unlocked. `new` must pass the same policy as at
    /// create ([`WeakMasterPassword`]).
    ///
    /// ```
    /// # use vault_core::crypto::MasterPassword;
    /// # use vault_core::session::{Session, SessionConfig};
    /// # use vault_core::storage::SqliteStore;
    /// # let dir = tempfile::tempdir()?;
    /// let old = MasterPassword::new("correct horse battery".into());
    /// let mut session = Session::create_insecure_for_tests(
    ///     SqliteStore::new(dir.path())?, "alice", &old, SessionConfig::default(),
    /// )?;
    /// session.change_master_password(&old, &MasterPassword::new("tr0ub4dor & 3 staples".into()))?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn change_master_password(
        &mut self,
        current: &MasterPassword,
        new: &MasterPassword,
    ) -> Result<(), SessionError> {
        let started = self.config.clock.now();
        let vault = self.vault()?;
        master_password_policy::check(new)?;
        let plaintext = body::encode(&vault.secrets);
        let (key, sealed) = match crypto::change_master_password(
            &vault.header,
            current,
            new,
            &plaintext,
        ) {
            Err(CryptoError::UnlockFailed) => {
                tracing::warn!(event = "master_password_change_failed", vaultname = %self.vaultname);
                wait_out_failure(self.config.clock.as_ref(), started);
                return Err(SessionError::UnlockFailed);
            }
            result => result?,
        };
        self.write(&sealed)?;
        let vault = self.open.as_mut().expect("written while unlocked");
        vault.key = key;
        vault.header = sealed.header;
        self.check_memory_locked(plaintext.is_memory_locked());
        tracing::info!(event = "master_password_changed", vaultname = %self.vaultname);
        Ok(())
    }

    /// Locks the vault: ends the session and wipes its keys and secrets.
    ///
    /// ```
    /// # use vault_core::crypto::MasterPassword;
    /// # use vault_core::session::{Session, SessionConfig};
    /// # use vault_core::storage::SqliteStore;
    /// # let dir = tempfile::tempdir()?;
    /// # let password = MasterPassword::new("correct horse battery".into());
    /// let session = Session::create_insecure_for_tests(
    ///     SqliteStore::new(dir.path())?, "alice", &password, SessionConfig::default(),
    /// )?;
    /// session.lock(); // `session` can't be used any more
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn lock(mut self) {
        if self.is_unlocked() {
            tracing::info!(event = "locked", vaultname = %self.vaultname);
        }
        // Dropping `self` zeroizes the vault key, the secrets and their locked pages.
    }

    /// The open vault, after auto-locking if idle; counts as activity.
    ///
    /// ```ignore
    /// let vault = self.vault()?;
    /// ```
    fn vault(&mut self) -> Result<&mut OpenVault, SessionError> {
        let now = self.config.clock.now();
        self.lock_if_idle(now);
        if self.open.is_some() {
            self.last_used = now;
        }
        self.open.as_mut().ok_or(SessionError::Locked)
    }

    /// Wipes the open vault if it has been idle for the timeout or longer.
    ///
    /// ```ignore
    /// self.lock_if_idle(self.config.clock.now());
    /// ```
    fn lock_if_idle(&mut self, now: Instant) {
        let idle = now.saturating_duration_since(self.last_used);
        if self.open.is_some() && idle >= self.config.idle_timeout {
            self.open = None;
            tracing::info!(event = "auto_locked", vaultname = %self.vaultname);
        }
    }

    /// Seals the current secrets as the next revision and writes them; on failure
    /// applies `undo`, so memory keeps matching the disk.
    ///
    /// ```ignore
    /// self.persist(Undo::Pop)?;
    /// ```
    fn persist(&mut self, undo: Undo) -> Result<(), SessionError> {
        let vault = self.open.as_mut().expect("persisted while unlocked");
        let plaintext = body::encode(&vault.secrets);
        let result = crypto::seal(&vault.key, &vault.header, &plaintext)
            .map_err(SessionError::from)
            .and_then(|sealed| {
                self.write(&sealed)?;
                Ok(sealed.header)
            });
        match result {
            Ok(header) => {
                self.open.as_mut().expect("written while unlocked").header = header;
                self.check_memory_locked(plaintext.is_memory_locked());
                Ok(())
            }
            Err(err) => {
                // After a conflict the session is locked and the secrets are already gone.
                if let Some(vault) = self.open.as_mut() {
                    undo.apply(&mut vault.secrets);
                }
                Err(err)
            }
        }
    }

    /// Writes `sealed` to storage. A conflict means another session saved first: this
    /// session locks, since its secrets no longer match the vault.
    ///
    /// ```ignore
    /// self.write(&sealed)?;
    /// ```
    fn write(&mut self, sealed: &SealedVault) -> Result<(), SessionError> {
        match self.store.save(&self.vaultname, sealed) {
            Err(StorageError::Conflict) => {
                self.open = None;
                tracing::warn!(event = "locked_on_conflict", vaultname = %self.vaultname);
                Err(SessionError::Conflict)
            }
            result => result.map_err(SessionError::from),
        }
    }

    /// Logs one `memory_lock_unavailable` warning per session if the vault key, the
    /// body (`body_locked`) or any hidden value couldn't be locked out of swap.
    ///
    /// ```ignore
    /// self.check_memory_locked(plaintext.is_memory_locked());
    /// ```
    fn check_memory_locked(&mut self, body_locked: bool) {
        let Some(vault) = &self.open else { return };
        let locked = body_locked
            && vault.key.is_memory_locked()
            && vault.secrets.iter().all(Secret::is_memory_locked);
        if !locked && !self.warned_memory_unlocked {
            self.warned_memory_unlocked = true;
            tracing::warn!(event = "memory_lock_unavailable", vaultname = %self.vaultname);
        }
    }
}

impl Undo {
    /// Puts `secrets` back the way they were before the change.
    ///
    /// ```ignore
    /// Undo::Pop.apply(&mut vault.secrets);
    /// ```
    fn apply(self, secrets: &mut Vec<Secret>) {
        match self {
            Self::Pop => drop(secrets.pop()),
            Self::Restore(i, secret) => secrets[i] = secret,
            Self::Insert(i, secret) => secrets.insert(i, secret),
        }
    }
}

/// Loads, unlocks and decrypts `vaultname`'s vault. Returns the decrypted body too, so
/// the caller can check its memory was locked.
///
/// Security: a missing vault runs [`crypto::simulate_unlock`] and fails like a wrong
/// master password; see [`Session::unlock`].
///
/// ```ignore
/// let (vault, plaintext) = open_vault(&store, &vaultname, &password)?;
/// ```
fn open_vault(
    store: &impl VaultStore,
    vaultname: &Vaultname,
    password: &MasterPassword,
) -> Result<(OpenVault, Plaintext), SessionError> {
    let sealed = match store.load(vaultname) {
        Err(StorageError::NotFound) => {
            // Only the cost matters; even a randomness failure must fail the same way.
            let _ = crypto::simulate_unlock(password);
            tracing::warn!(event = "unlock_failed");
            return Err(SessionError::UnlockFailed);
        }
        result => result?,
    };
    let key = crypto::unlock(&sealed.header, password).inspect_err(|err| {
        if *err == CryptoError::UnlockFailed {
            tracing::warn!(event = "unlock_failed", vaultname = %vaultname);
        }
    })?;
    let plaintext = crypto::open_body(&key, &sealed)?;
    let secrets = body::decode(&plaintext).map_err(|_| SessionError::VaultUnreadable)?;
    let vault = OpenVault {
        key,
        header: sealed.header,
        secrets,
    };
    Ok((vault, plaintext))
}

/// Sleeps until [`MIN_UNLOCK_FAILURE`] has passed since `started`.
///
/// ```ignore
/// wait_out_failure(config.clock.as_ref(), started);
/// ```
fn wait_out_failure(clock: &dyn Clock, started: Instant) {
    let elapsed = clock.now().saturating_duration_since(started);
    clock.sleep(MIN_UNLOCK_FAILURE.saturating_sub(elapsed));
}
