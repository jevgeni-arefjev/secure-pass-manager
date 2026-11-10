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
//! - Audit events go to the configured [`AuditSink`] only after their action succeeded,
//!   and name at most a secret's title (ADR-0010). A failed write never blocks the
//!   action; it gives one `audit_write_failed` warning per session. A failed unlock is
//!   recorded within the minimum failure delay, and only for a vault that exists.
//!
//! ```
//! use std::sync::Arc;
//! use vault_core::audit::FileSink;
//! use vault_core::crypto::MasterPassword;
//! use vault_core::session::{HiddenValue, SessionError, Secret, Session, SessionConfig};
//! use vault_core::storage::FileStore;
//!
//! let dir = tempfile::tempdir()?;
//! let config = || SessionConfig::new(Arc::new(FileSink::new(dir.path())));
//! let password = MasterPassword::new("correct horse battery".into());
//! let mut session =
//!     Session::create_insecure_for_tests(FileStore::new(dir.path())?, "alice", &password, config())?;
//! session.save(Secret::new("GitHub").with_password(HiddenValue::new("s3cret!".into())))?;
//! session.lock();
//!
//! let mut session = Session::unlock(FileStore::new(dir.path())?, "alice", &password, config())?;
//! let shown = session.reveal("github", |github| {
//!     Ok::<_, SessionError>(github.password().map(|p| p.reveal().to_owned()))
//! })?;
//! assert_eq!(shown.as_deref(), Some("s3cret!"));
//! assert_eq!(session.audit_log(20)?.len(), 5); // created, saved, locked, unlocked, revealed
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod body;
mod clock;
mod master_password_policy;
mod secret;

use std::fmt;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::DateTime;

use crate::audit::{AuditSink, Event, Line, Record};
use crate::backup::{self, BackupError, BackupFile, Destination};
use crate::crypto::{self, CryptoError, Header, MasterPassword, Plaintext, SealedVault, VaultKey};
use crate::storage::{StorageError, VaultStore, Vaultname};

pub use clock::{Clock, SystemClock};
pub use master_password_policy::{
    MAX_MASTER_PASSWORD_CHARS, MIN_MASTER_PASSWORD_CHARS, WeakMasterPassword,
    check as check_master_password,
};
pub use secret::{
    CustomField, CustomFieldPart, FieldProblem, FieldValue, HiddenValue, InvalidSecret, Secret,
    SecretField, check, is_unsafe_char,
};

/// Idle time after which a session locks itself, unless configured otherwise.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Shortest time any failed unlock takes, so failures can't be told apart by timing.
pub const MIN_UNLOCK_FAILURE: Duration = Duration::from_secs(1);

/// How a session behaves; front ends start from [`SessionConfig::new`].
///
/// ```
/// use std::sync::Arc;
/// use std::time::Duration;
/// use vault_core::audit::FileSink;
/// use vault_core::session::SessionConfig;
///
/// let config = SessionConfig {
///     idle_timeout: Duration::from_secs(60),
///     ..SessionConfig::new(Arc::new(FileSink::new("/home/alice/.local/share/secure-pass-manager/vaults")))
/// };
/// ```
pub struct SessionConfig {
    /// Idle time after which the session locks itself.
    pub idle_timeout: Duration,
    /// Where time comes from; [`SystemClock`] outside tests.
    pub clock: Arc<dyn Clock>,
    /// Where audit events go (ADR-0010).
    pub audit: Arc<dyn AuditSink>,
}

impl SessionConfig {
    /// A 5-minute idle timeout on the system clock, recording audit events to `audit`.
    /// There is no default sink, so no session runs without an audit log by accident.
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use vault_core::audit::MemorySink;
    /// # use vault_core::session::{SessionConfig, DEFAULT_IDLE_TIMEOUT};
    /// let config = SessionConfig::new(Arc::new(MemorySink::default()));
    /// assert_eq!(config.idle_timeout, DEFAULT_IDLE_TIMEOUT);
    /// ```
    #[must_use]
    pub fn new(audit: Arc<dyn AuditSink>) -> Self {
        Self {
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            clock: Arc::new(SystemClock),
            audit,
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
#[derive(Clone, Debug, PartialEq, Eq)]
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
    /// A secret breaks the field rules; carries every problem found.
    InvalidSecret(InvalidSecret),
    /// Saving would make the vault file too large to open again. Nothing was written
    /// and the session stays unlocked; remove or shorten secrets to make room.
    VaultFull,
    /// The vault file, its header or its body isn't something this build can read.
    VaultUnreadable,
    /// The file system failed, with the [`io::ErrorKind`] it failed with
    /// ([`crate::storage::LOCK_HELD_TOO_LONG`] if another session held the vault's lock
    /// too long).
    Storage(io::ErrorKind),
    /// The OS random number generator failed.
    Randomness,
    /// The audit log couldn't be read.
    AuditLog,
    /// A backup couldn't be made.
    Backup(BackupError),
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
            Self::VaultFull => StorageError::VaultFull.fmt(f),
            Self::VaultUnreadable => f.write_str("vault file can't be read"),
            Self::Storage(kind) => StorageError::Io(*kind).fmt(f),
            Self::Randomness => CryptoError::Randomness.fmt(f),
            Self::AuditLog => f.write_str("audit log can't be read"),
            Self::Backup(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for SessionError {}

/// What failed in an internal failure (ADR-0014). Its [`name`](Self::name) is the
/// `cause` of an `internal_error` diagnostic; a front end adds its own causes for
/// failures of its own (e.g. a panic on the web).
///
/// ```
/// use vault_core::session::InternalCause;
/// assert_eq!(InternalCause::VaultUnreadable.name(), "vault_unreadable");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InternalCause {
    /// Reading or writing the vault file or its vault home.
    Storage,
    /// Writing or verifying a backup.
    Backup,
    /// The OS random number generator.
    Randomness,
    /// A vault file, header or body this build can't read.
    VaultUnreadable,
    /// Reading the audit log.
    AuditLog,
}

impl InternalCause {
    /// The fixed name logged as the diagnostic's `cause`.
    ///
    /// Security: fixed text, safe to log.
    ///
    /// ```
    /// # use vault_core::session::InternalCause;
    /// assert_eq!(InternalCause::AuditLog.name(), "audit_log");
    /// ```
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Storage => "storage",
            Self::Backup => "backup",
            Self::Randomness => "randomness",
            Self::VaultUnreadable => "vault_unreadable",
            Self::AuditLog => "audit_log",
        }
    }
}

/// What an internal failure (ADR-0014) was, for a front end's diagnostic and, on the
/// CLI, its message: a fixed name for what failed and its cause kind, where there is
/// one.
///
/// Security: holds only fixed names and an [`io::ErrorKind`], never an OS message,
/// path, vaultname or anything typed, so it is safe to log.
///
/// ```
/// use std::io::ErrorKind;
/// use vault_core::session::{InternalCause, InternalFailure, SessionError};
/// assert_eq!(
///     SessionError::Storage(ErrorKind::StorageFull).internal_failure(),
///     Some(InternalFailure { cause: InternalCause::Storage, kind: Some(ErrorKind::StorageFull) })
/// );
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InternalFailure {
    /// What failed.
    pub cause: InternalCause,
    /// The file system's cause kind, if the failure came from the file system.
    pub kind: Option<io::ErrorKind>,
}

impl SessionError {
    /// The internal failure this error is, or `None` for an input mistake, a security
    /// refusal or an ended session (ADR-0014), which a front end reports by its message
    /// alone.
    ///
    /// ```
    /// # use vault_core::session::{InternalCause, InternalFailure, SessionError};
    /// assert_eq!(SessionError::SecretNotFound.internal_failure(), None);
    /// assert_eq!(
    ///     SessionError::Randomness.internal_failure(),
    ///     Some(InternalFailure { cause: InternalCause::Randomness, kind: None })
    /// );
    /// ```
    #[must_use]
    pub fn internal_failure(&self) -> Option<InternalFailure> {
        let (cause, kind) = match self {
            Self::Storage(kind) => (InternalCause::Storage, Some(*kind)),
            Self::Backup(BackupError::Io(kind)) => (InternalCause::Backup, Some(*kind)),
            Self::Backup(BackupError::Unverified) => (InternalCause::Backup, None),
            Self::Randomness => (InternalCause::Randomness, None),
            Self::VaultUnreadable => (InternalCause::VaultUnreadable, None),
            Self::AuditLog => (InternalCause::AuditLog, None),
            Self::UnlockFailed
            | Self::InvalidVaultname
            | Self::VaultExists
            | Self::WeakMasterPassword(_)
            | Self::Locked
            | Self::Conflict
            | Self::SecretNotFound
            | Self::InvalidSecret(_)
            | Self::VaultFull
            | Self::Backup(
                BackupError::NotAFilePath
                | BackupError::NoDirectory
                | BackupError::InsideVaultDirectory
                | BackupError::Exists,
            ) => return None,
        };
        Some(InternalFailure { cause, kind })
    }
}

impl From<StorageError> for SessionError {
    /// Maps a storage failure; `NotFound` outside unlock means the file vanished, and
    /// becomes [`SessionError::Storage`] of [`io::ErrorKind::NotFound`].
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
            StorageError::VaultFull => Self::VaultFull,
            StorageError::NotFound => Self::Storage(io::ErrorKind::NotFound),
            StorageError::Io(kind) => Self::Storage(kind),
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

impl From<BackupError> for SessionError {
    /// Wraps a backup failure.
    ///
    /// ```
    /// # use vault_core::{backup::BackupError, session::SessionError};
    /// assert_eq!(SessionError::from(BackupError::Exists), SessionError::Backup(BackupError::Exists));
    /// ```
    fn from(err: BackupError) -> Self {
        Self::Backup(err)
    }
}

impl From<InvalidSecret> for SessionError {
    /// Wraps a field rule failure.
    ///
    /// ```ignore
    /// secret.validate()?; // an InvalidSecret becomes SessionError::InvalidSecret
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
/// # use std::sync::Arc;
/// # use vault_core::audit::MemorySink;
/// # use vault_core::crypto::MasterPassword;
/// # use vault_core::session::{Session, SessionConfig};
/// # use vault_core::storage::FileStore;
/// # let dir = tempfile::tempdir()?;
/// # let store = FileStore::new(dir.path())?;
/// let password = MasterPassword::new("correct horse battery".into());
/// let session =
///     Session::create_insecure_for_tests(store, "alice", &password, SessionConfig::new(Arc::new(MemorySink::default())))?;
/// session.lock();
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct Session<S: VaultStore> {
    /// Where the vault file is loaded from and saved to.
    store: S,
    /// The vault this session unlocked; it can open no other.
    vaultname: Vaultname,
    /// Idle timeout, clock and audit sink.
    config: SessionConfig,
    /// `None` once auto-locked or locked by a conflict.
    open: Option<OpenVault>,
    /// When the session was last used, for auto-lock.
    last_used: Instant,
    /// Whether the "hidden values are not in locked memory" warning was already given.
    warned_memory_unlocked: bool,
    /// Whether the "audit log could not be written" warning was already given.
    warned_audit_failed: bool,
}

/// What an unlocked session holds.
struct OpenVault {
    /// The vault key, which decrypts the body.
    key: VaultKey,
    /// The header of the vault file as last loaded or saved.
    header: Header,
    /// Every secret in the vault, decrypted.
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
    /// # use std::sync::Arc;
    /// # use vault_core::audit::MemorySink;
    /// # use vault_core::crypto::MasterPassword;
    /// # use vault_core::session::{Session, SessionConfig};
    /// # use vault_core::storage::FileStore;
    /// let store = FileStore::new("/home/alice/.local/share/secure-pass-manager/vaults")?;
    /// let password = MasterPassword::new("correct horse battery".into());
    /// let session = Session::create(store, "alice", &password, SessionConfig::new(Arc::new(MemorySink::default())))?;
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
    /// # use std::sync::Arc;
    /// # use vault_core::audit::MemorySink;
    /// # use vault_core::crypto::MasterPassword;
    /// # use vault_core::session::{Session, SessionConfig};
    /// # use vault_core::storage::FileStore;
    /// # let dir = tempfile::tempdir()?;
    /// let password = MasterPassword::new("correct horse battery".into());
    /// let session = Session::create_insecure_for_tests(
    ///     FileStore::new(dir.path())?, "alice", &password, SessionConfig::new(Arc::new(MemorySink::default())),
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
        let vault = OpenVault {
            key,
            header: sealed.header,
            secrets,
        };
        let mut session = Self::opened(store, vaultname, config, vault, &plaintext);
        session.record(Event::VaultCreated);
        Ok(session)
    }

    /// Unlocks the vault named `vaultname` with `password`.
    ///
    /// Security: a missing vault, a wrong master password and a tampered header all
    /// give [`SessionError::UnlockFailed`] after the same Argon2id cost and at least one
    /// second. A wrong master password is recorded in the vault's audit log within that
    /// second, so the write can't reveal that the vault exists; a missing vault records
    /// nothing and creates no file.
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use vault_core::audit::MemorySink;
    /// # use vault_core::crypto::MasterPassword;
    /// # use vault_core::session::{Session, SessionConfig, SessionError};
    /// # use vault_core::storage::FileStore;
    /// # let dir = tempfile::tempdir()?;
    /// # let password = MasterPassword::new("correct horse battery".into());
    /// # let config = || SessionConfig::new(Arc::new(MemorySink::default()));
    /// # Session::create_insecure_for_tests(FileStore::new(dir.path())?, "alice", &password, config())?;
    /// let wrong = MasterPassword::new("wrong guess".into());
    /// let result = Session::unlock(FileStore::new(dir.path())?, "alice", &wrong, config());
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
        match open_vault(&store, &vaultname, password, &config) {
            Ok((vault, plaintext)) => {
                let mut session = Self::opened(store, vaultname, config, vault, &plaintext);
                session.record(Event::Unlocked);
                Ok(session)
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
            warned_audit_failed: false,
        };
        session.check_memory_locked(plaintext.is_memory_locked());
        session
    }

    /// The vaultname this session unlocked.
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use vault_core::audit::MemorySink;
    /// # use vault_core::crypto::MasterPassword;
    /// # use vault_core::session::{Session, SessionConfig};
    /// # use vault_core::storage::FileStore;
    /// # let dir = tempfile::tempdir()?;
    /// # let password = MasterPassword::new("correct horse battery".into());
    /// let session = Session::create_insecure_for_tests(
    ///     FileStore::new(dir.path())?, "Alice", &password, SessionConfig::new(Arc::new(MemorySink::default())),
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
    /// # use std::sync::Arc;
    /// # use vault_core::audit::MemorySink;
    /// # use vault_core::crypto::MasterPassword;
    /// # use vault_core::session::{Session, SessionConfig};
    /// # use vault_core::storage::FileStore;
    /// # let dir = tempfile::tempdir()?;
    /// # let password = MasterPassword::new("correct horse battery".into());
    /// # let mut session = Session::create_insecure_for_tests(FileStore::new(dir.path())?, "alice", &password, SessionConfig::new(Arc::new(MemorySink::default())))?;
    /// assert!(session.is_unlocked());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn is_unlocked(&mut self) -> bool {
        self.lock_if_idle(self.config.clock.now());
        self.open.is_some()
    }

    /// The secret titled `title` (ignoring case and surrounding spaces), for showing it
    /// masked. To show or copy hidden fields, use [`Session::reveal`], which records it.
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use vault_core::audit::MemorySink;
    /// # use vault_core::crypto::MasterPassword;
    /// # use vault_core::session::{Secret, Session, SessionConfig};
    /// # use vault_core::storage::FileStore;
    /// # let dir = tempfile::tempdir()?;
    /// # let password = MasterPassword::new("correct horse battery".into());
    /// # let mut session = Session::create_insecure_for_tests(FileStore::new(dir.path())?, "alice", &password, SessionConfig::new(Arc::new(MemorySink::default())))?;
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

    /// Reveals the secret titled `title`: runs `f` on it, where the front end shows or
    /// copies its hidden fields, and records the reveal if `f` succeeds.
    ///
    /// Security: front ends must reveal hidden fields only through this, never through
    /// [`Session::get`], so every reveal is in the audit log. A failing `f` records
    /// nothing, as nothing was revealed.
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use vault_core::audit::MemorySink;
    /// # use vault_core::crypto::MasterPassword;
    /// # use vault_core::session::{HiddenValue, Secret, Session, SessionConfig, SessionError};
    /// # use vault_core::storage::FileStore;
    /// # let dir = tempfile::tempdir()?;
    /// # let password = MasterPassword::new("correct horse battery".into());
    /// # let mut session = Session::create_insecure_for_tests(FileStore::new(dir.path())?, "alice", &password, SessionConfig::new(Arc::new(MemorySink::default())))?;
    /// session.save(Secret::new("GitHub").with_password(HiddenValue::new("s3cret!".into())))?;
    /// session.reveal("github", |secret| {
    ///     println!("{}", secret.password().map_or("", HiddenValue::reveal));
    ///     Ok::<_, SessionError>(())
    /// })?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn reveal<R, E: From<SessionError>>(
        &mut self,
        title: &str,
        f: impl FnOnce(&Secret) -> Result<R, E>,
    ) -> Result<R, E> {
        let secret = self.get(title)?;
        let title = secret.title().to_owned();
        let result = f(secret)?;
        self.record(Event::SecretRevealed { title });
        Ok(result)
    }

    /// Up to `limit` of this vault's audit log lines, newest first.
    ///
    /// Security: only the vault this session unlocked; [`SessionError::Locked`] once
    /// locked. Titles in it are plaintext as stored: escape them before display.
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use vault_core::audit::MemorySink;
    /// # use vault_core::crypto::MasterPassword;
    /// # use vault_core::session::{Session, SessionConfig};
    /// # use vault_core::storage::FileStore;
    /// # let dir = tempfile::tempdir()?;
    /// # let password = MasterPassword::new("correct horse battery".into());
    /// # let mut session = Session::create_insecure_for_tests(FileStore::new(dir.path())?, "alice", &password, SessionConfig::new(Arc::new(MemorySink::default())))?;
    /// let newest = session.audit_log(20)?;
    /// assert_eq!(newest.len(), 1); // the vault was just created
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn audit_log(&mut self, limit: usize) -> Result<Vec<Line>, SessionError> {
        self.vault()?;
        self.config
            .audit
            .read_recent(&self.vaultname, limit)
            .map_err(|_| SessionError::AuditLog)
    }

    /// Whether a secret titled `title` exists (ignoring case), e.g. to ask before
    /// overwriting it.
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use vault_core::audit::MemorySink;
    /// # use vault_core::crypto::MasterPassword;
    /// # use vault_core::session::{Session, SessionConfig};
    /// # use vault_core::storage::FileStore;
    /// # let dir = tempfile::tempdir()?;
    /// # let password = MasterPassword::new("correct horse battery".into());
    /// # let mut session = Session::create_insecure_for_tests(FileStore::new(dir.path())?, "alice", &password, SessionConfig::new(Arc::new(MemorySink::default())))?;
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
    /// # use std::sync::Arc;
    /// # use vault_core::audit::MemorySink;
    /// # use vault_core::crypto::MasterPassword;
    /// # use vault_core::session::{Secret, Session, SessionConfig};
    /// # use vault_core::storage::FileStore;
    /// # let dir = tempfile::tempdir()?;
    /// # let password = MasterPassword::new("correct horse battery".into());
    /// # let mut session = Session::create_insecure_for_tests(FileStore::new(dir.path())?, "alice", &password, SessionConfig::new(Arc::new(MemorySink::default())))?;
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
    /// conflict the session locks ([`SessionError::Conflict`]); on any other failure,
    /// including a vault that would grow too large to open ([`SessionError::VaultFull`]),
    /// nothing changes and the session stays unlocked.
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use vault_core::audit::MemorySink;
    /// # use vault_core::crypto::MasterPassword;
    /// # use vault_core::session::{HiddenValue, Saved, Secret, Session, SessionConfig};
    /// # use vault_core::storage::FileStore;
    /// # let dir = tempfile::tempdir()?;
    /// # let password = MasterPassword::new("correct horse battery".into());
    /// # let mut session = Session::create_insecure_for_tests(FileStore::new(dir.path())?, "alice", &password, SessionConfig::new(Arc::new(MemorySink::default())))?;
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
        let title = secret.title().to_owned();
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
        self.record(match saved {
            Saved::Added => Event::SecretAdded { title },
            Saved::Replaced => Event::SecretReplaced { title },
        });
        Ok(saved)
    }

    /// Removes the secret titled `title` (ignoring case) and writes the vault at once.
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use vault_core::audit::MemorySink;
    /// # use vault_core::crypto::MasterPassword;
    /// # use vault_core::session::{Secret, Session, SessionConfig, SessionError};
    /// # use vault_core::storage::FileStore;
    /// # let dir = tempfile::tempdir()?;
    /// # let password = MasterPassword::new("correct horse battery".into());
    /// # let mut session = Session::create_insecure_for_tests(FileStore::new(dir.path())?, "alice", &password, SessionConfig::new(Arc::new(MemorySink::default())))?;
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
        let title = removed.title().to_owned();
        self.persist(Undo::Insert(i, removed))?;
        self.record(Event::SecretRemoved { title });
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
    /// # use std::sync::Arc;
    /// # use vault_core::audit::MemorySink;
    /// # use vault_core::crypto::MasterPassword;
    /// # use vault_core::session::{Session, SessionConfig};
    /// # use vault_core::storage::FileStore;
    /// # let dir = tempfile::tempdir()?;
    /// let old = MasterPassword::new("correct horse battery".into());
    /// let mut session = Session::create_insecure_for_tests(
    ///     FileStore::new(dir.path())?, "alice", &old, SessionConfig::new(Arc::new(MemorySink::default())),
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
        let (key, sealed) =
            match crypto::change_master_password(&vault.header, current, new, &plaintext) {
                Err(CryptoError::UnlockFailed) => {
                    self.record(Event::MasterPasswordChangeFailed);
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
        self.record(Event::MasterPasswordChanged);
        Ok(())
    }

    /// Writes a backup of this vault to `dest` and returns the revision it holds.
    ///
    /// The vault file is copied as stored, never decrypted for output. The copy is
    /// written next to `dest`, read back, checked to be byte-for-byte the stored vault
    /// and to open with this session's vault key, and only then put in place.
    ///
    /// Security: if the stored vault isn't the revision this session holds (another
    /// session saved first), the session locks as on a save conflict
    /// ([`SessionError::Conflict`]), so a backup always opens with the master password
    /// this session was unlocked with. The audit event records the revision, not the
    /// path.
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use vault_core::audit::MemorySink;
    /// # use vault_core::backup::Destination;
    /// # use vault_core::crypto::MasterPassword;
    /// # use vault_core::session::{Session, SessionConfig};
    /// # use vault_core::storage::FileStore;
    /// let vaults = tempfile::tempdir()?;
    /// let elsewhere = tempfile::tempdir()?;
    /// # let password = MasterPassword::new("correct horse battery".into());
    /// let mut session = Session::create_insecure_for_tests(
    ///     FileStore::new(vaults.path())?, "alice", &password, SessionConfig::new(Arc::new(MemorySink::default())),
    /// )?;
    /// let dest = Destination::new(&elsewhere.path().join("alice.vault"), vaults.path())?;
    /// assert_eq!(session.backup(&dest)?, 0);
    /// assert!(elsewhere.path().join("alice.vault").is_file());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn backup(&mut self, dest: &Destination) -> Result<u64, SessionError> {
        let stored = self.stored_as_held()?;
        let staged = backup::stage(dest, &stored)?;
        let key = &self.open.as_ref().expect("checked unlocked above").key;
        // The decrypted body is only checked, never kept: dropping it wipes it.
        let verified = staged
            .read_back()
            .is_ok_and(|copy| copy == stored && crypto::open_body(key, &copy).is_ok());
        if !verified {
            return Err(BackupError::Unverified.into());
        }
        staged.commit()?;
        let revision = stored.header.revision();
        self.record(Event::BackupCreated { revision });
        Ok(revision)
    }

    /// Returns a backup of this vault whole, e.g. for a browser to download, instead of
    /// writing it to a [`Destination`]; the backup is recorded as made once it is
    /// handed out.
    ///
    /// Security: the vault file is returned as stored, never decrypted for output,
    /// after the same checks as [`Session::backup`]: it must be the revision this
    /// session holds (else the session locks, [`SessionError::Conflict`], so the backup
    /// always opens with the master password this session was unlocked with) and must
    /// open with this session's vault key ([`BackupError::Unverified`] otherwise; the
    /// decrypted body is only checked, then wiped).
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use vault_core::audit::MemorySink;
    /// # use vault_core::crypto::MasterPassword;
    /// # use vault_core::session::{Session, SessionConfig};
    /// # use vault_core::storage::FileStore;
    /// # let dir = tempfile::tempdir()?;
    /// # let password = MasterPassword::new("correct horse battery".into());
    /// let mut session = Session::create_insecure_for_tests(
    ///     FileStore::new(dir.path())?, "alice", &password, SessionConfig::new(Arc::new(MemorySink::default())),
    /// )?;
    /// let file = session.backup_file()?;
    /// assert_eq!(file.revision(), 0);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn backup_file(&mut self) -> Result<BackupFile, SessionError> {
        let stored = self.stored_as_held()?;
        let key = &self.open.as_ref().expect("checked unlocked above").key;
        // The decrypted body is only checked, never kept: dropping it wipes it.
        if crypto::open_body(key, &stored).is_err() {
            return Err(BackupError::Unverified.into());
        }
        let file = BackupFile::of(&stored);
        self.record(Event::BackupCreated {
            revision: file.revision(),
        });
        Ok(file)
    }

    /// The vault file as stored, if it is the revision this session holds.
    ///
    /// Security: otherwise the session locks as on a save conflict
    /// ([`SessionError::Conflict`]), so a backup always opens with the master password
    /// this session was unlocked with.
    ///
    /// ```ignore
    /// let stored = self.stored_as_held()?;
    /// ```
    fn stored_as_held(&mut self) -> Result<SealedVault, SessionError> {
        let held = self.vault()?.header.clone();
        let stored = self.store.load(&self.vaultname)?;
        if stored.header != held {
            return Err(self.lock_on_conflict());
        }
        Ok(stored)
    }

    /// Locks the vault: ends the session and wipes its keys and secrets.
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use vault_core::audit::MemorySink;
    /// # use vault_core::crypto::MasterPassword;
    /// # use vault_core::session::{Session, SessionConfig};
    /// # use vault_core::storage::FileStore;
    /// # let dir = tempfile::tempdir()?;
    /// # let password = MasterPassword::new("correct horse battery".into());
    /// let session = Session::create_insecure_for_tests(
    ///     FileStore::new(dir.path())?, "alice", &password, SessionConfig::new(Arc::new(MemorySink::default())),
    /// )?;
    /// session.lock(); // `session` can't be used any more
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn lock(self) {
        self.lock_recording(Event::Locked);
    }

    /// Locks the vault because a termination signal arrived, like [`Session::lock`]
    /// but recorded as such.
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use vault_core::audit::MemorySink;
    /// # use vault_core::crypto::MasterPassword;
    /// # use vault_core::session::{Session, SessionConfig};
    /// # use vault_core::storage::FileStore;
    /// # let dir = tempfile::tempdir()?;
    /// # let password = MasterPassword::new("correct horse battery".into());
    /// let session = Session::create_insecure_for_tests(
    ///     FileStore::new(dir.path())?, "alice", &password, SessionConfig::new(Arc::new(MemorySink::default())),
    /// )?;
    /// session.lock_on_signal(); // e.g. from a SIGTERM handler
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn lock_on_signal(self) {
        self.lock_recording(Event::TerminatedBySignal);
    }

    /// Locks the vault because a limit the front end sets has run out (vault-web's
    /// absolute session lifetime), like [`Session::lock`] but recorded as an auto-lock.
    /// A session that already auto-locked on its idle timeout records nothing more.
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use vault_core::audit::MemorySink;
    /// # use vault_core::crypto::MasterPassword;
    /// # use vault_core::session::{Session, SessionConfig};
    /// # use vault_core::storage::FileStore;
    /// # let dir = tempfile::tempdir()?;
    /// # let password = MasterPassword::new("correct horse battery".into());
    /// let session = Session::create_insecure_for_tests(
    ///     FileStore::new(dir.path())?, "alice", &password, SessionConfig::new(Arc::new(MemorySink::default())),
    /// )?;
    /// session.auto_lock(); // e.g. 8 h after unlock
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn auto_lock(self) {
        self.lock_recording(Event::AutoLocked);
    }

    /// Ends the session, recording `event` if it was still unlocked (an auto-lock or
    /// conflict was already recorded).
    ///
    /// ```ignore
    /// self.lock_recording(Event::Locked);
    /// ```
    fn lock_recording(mut self, event: Event) {
        if self.is_unlocked() {
            self.record(event);
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
            self.record(Event::AutoLocked);
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
            Err(StorageError::Conflict) => Err(self.lock_on_conflict()),
            result => result.map_err(SessionError::from),
        }
    }

    /// Locks the session because the stored vault is no longer the one it holds, and
    /// records it; returns the error to report.
    ///
    /// ```ignore
    /// return Err(self.lock_on_conflict());
    /// ```
    fn lock_on_conflict(&mut self) -> SessionError {
        self.open = None;
        self.record(Event::LockedOnConflict);
        SessionError::Conflict
    }

    /// Records `event` in this vault's audit log. A failed write never fails the caller;
    /// it logs one `audit_write_failed` warning per session.
    ///
    /// ```ignore
    /// self.record(Event::Locked);
    /// ```
    fn record(&mut self, event: Event) {
        if !append_event(&self.config, &self.vaultname, event) && !self.warned_audit_failed {
            self.warned_audit_failed = true;
            tracing::warn!(event = "audit_write_failed", vaultname = %self.vaultname);
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
/// master password, recording nothing; a wrong master password for an existing vault
/// is recorded in its audit log. See [`Session::unlock`].
///
/// ```ignore
/// let (vault, plaintext) = open_vault(&store, &vaultname, &password, &config)?;
/// ```
fn open_vault(
    store: &impl VaultStore,
    vaultname: &Vaultname,
    password: &MasterPassword,
    config: &SessionConfig,
) -> Result<(OpenVault, Plaintext), SessionError> {
    let sealed = match store.load(vaultname) {
        Err(StorageError::NotFound) => {
            // Only the cost matters; even a randomness failure must fail the same way.
            let _ = crypto::simulate_unlock(password);
            return Err(SessionError::UnlockFailed);
        }
        result => result?,
    };
    let key = crypto::unlock(&sealed.header, password).inspect_err(|err| {
        if *err == CryptoError::UnlockFailed
            && !append_event(config, vaultname, Event::UnlockFailed)
        {
            tracing::warn!(event = "audit_write_failed", vaultname = %vaultname);
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

/// Title of the secret [`fill_vault_for_tests`] adds; remove it to make room again.
#[cfg(feature = "insecure-test-kdf")]
pub const FILLER_TITLE: &str = "filler";

/// Fills `vaultname`'s vault (unlocked with `password`) to the vault size limit: adds a
/// secret titled [`FILLER_TITLE`] whose notes make the vault file as large as it may be, with
/// its last padding block used up, so that no further secret fits. Its notes break the
/// field rules on purpose (as a vault from another build could), so it is written
/// straight into the body, past [`Session::save`].
///
/// Security: never for real vaults. Exists only with the `insecure-test-kdf` feature,
/// which release builds refuse.
///
/// ```
/// # use std::sync::Arc;
/// # use vault_core::audit::MemorySink;
/// # use vault_core::crypto::MasterPassword;
/// # use vault_core::session::{self, Secret, Session, SessionConfig, SessionError};
/// # use vault_core::storage::FileStore;
/// # let dir = tempfile::tempdir()?;
/// # let config = || SessionConfig::new(Arc::new(MemorySink::default()));
/// let password = MasterPassword::new("correct horse battery".into());
/// Session::create_insecure_for_tests(FileStore::new(dir.path())?, "alice", &password, config())?.lock();
/// session::fill_vault_for_tests(&FileStore::new(dir.path())?, "alice", &password)?;
/// let mut session = Session::unlock(FileStore::new(dir.path())?, "alice", &password, config())?;
/// assert_eq!(session.save(Secret::new("one more")), Err(SessionError::VaultFull));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[cfg(feature = "insecure-test-kdf")]
pub fn fill_vault_for_tests<S: VaultStore>(
    store: &S,
    vaultname: &str,
    password: &MasterPassword,
) -> Result<(), SessionError> {
    rewrite_body_for_tests(store, vaultname, password, |secrets| {
        secrets.push(Secret::new(FILLER_TITLE).with_notes("x"));
        let with_one_x = body::encode(secrets).as_bytes().len();
        let max = usize::try_from(crate::storage::MAX_VAULT_FILE_LEN).expect("fits in memory");
        let notes = "x".repeat(1 + crypto::largest_plaintext_len(max) - with_one_x);
        *secrets.last_mut().expect("just pushed") = Secret::new(FILLER_TITLE).with_notes(notes);
    })
}

/// Adds `secret` to `vaultname`'s vault (unlocked with `password`) as it is, without
/// trimming, normalising or checking it: a stand-in for a secret saved by a build with
/// older, looser field rules.
///
/// Security: never for real vaults. Exists only with the `insecure-test-kdf` feature,
/// which release builds refuse.
///
/// ```
/// # use std::sync::Arc;
/// # use vault_core::audit::MemorySink;
/// # use vault_core::crypto::MasterPassword;
/// # use vault_core::session::{self, Secret, Session, SessionConfig};
/// # use vault_core::storage::FileStore;
/// # let dir = tempfile::tempdir()?;
/// # let config = || SessionConfig::new(Arc::new(MemorySink::default()));
/// let password = MasterPassword::new("correct horse battery".into());
/// Session::create_insecure_for_tests(FileStore::new(dir.path())?, "alice", &password, config())?.lock();
/// let old = Secret::new("evil\u{202e}gpj.exe");
/// session::insert_unchecked_for_tests(&FileStore::new(dir.path())?, "alice", &password, old)?;
/// let mut session = Session::unlock(FileStore::new(dir.path())?, "alice", &password, config())?;
/// assert_eq!(session.list()?.len(), 1);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[cfg(feature = "insecure-test-kdf")]
pub fn insert_unchecked_for_tests<S: VaultStore>(
    store: &S,
    vaultname: &str,
    password: &MasterPassword,
    secret: Secret,
) -> Result<(), SessionError> {
    rewrite_body_for_tests(store, vaultname, password, |secrets| secrets.push(secret))
}

/// Opens `vaultname`'s vault with `password`, lets `change` edit its secrets directly,
/// and seals and saves the result, past every check of [`Session::save`].
///
/// Security: never for real vaults; only with the `insecure-test-kdf` feature.
///
/// ```ignore
/// rewrite_body_for_tests(store, "alice", &password, |secrets| secrets.clear())?;
/// ```
#[cfg(feature = "insecure-test-kdf")]
fn rewrite_body_for_tests<S: VaultStore>(
    store: &S,
    vaultname: &str,
    password: &MasterPassword,
    change: impl FnOnce(&mut Vec<Secret>),
) -> Result<(), SessionError> {
    let vaultname = Vaultname::parse(vaultname)?;
    let sealed = store.load(&vaultname)?;
    let key = crypto::unlock(&sealed.header, password)?;
    let plaintext = crypto::open_body(&key, &sealed)?;
    let mut secrets = body::decode(&plaintext).map_err(|_| SessionError::VaultUnreadable)?;
    change(&mut secrets);
    let changed = crypto::seal(&key, &sealed.header, &body::encode(&secrets))?;
    store.save(&vaultname, &changed)?;
    Ok(())
}

/// Appends `event`, stamped with the config's clock, to `vaultname`'s audit log;
/// `false` if the write failed.
///
/// ```ignore
/// if !append_event(&config, &vaultname, Event::UnlockFailed) { /* warn */ }
/// ```
fn append_event(config: &SessionConfig, vaultname: &Vaultname, event: Event) -> bool {
    let seconds = i64::try_from(config.clock.unix_time()).unwrap_or(i64::MAX);
    let time = DateTime::from_timestamp(seconds, 0).unwrap_or_default();
    config
        .audit
        .append(vaultname, &Record { time, event })
        .is_ok()
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
