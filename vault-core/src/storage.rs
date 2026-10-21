//! Storage module: vault files on disk.
//!
//! One SQLite file per vault, `<vault directory>/<vaultname>.vault`, holding one row:
//! the encoded header, the encrypted body and the revision (ADR-0006). Storage only
//! ever handles what crypto sealed ([`SealedVault`]); it never sees plaintext or keys.
//!
//! Security:
//! - Vaultnames are allowlisted by [`Vaultname`] before they become file names.
//! - Vault files may come from untrusted places, so every connection is opened with
//!   SQLite's defensive mode and untrusted schema, and the file's `application_id` and
//!   `user_version` are checked before any table is read.
//! - `secure_delete` zeroes freed pages, so a save leaves no old ciphertext (e.g. a
//!   header wrapped under a rotated master password) in the file.
//! - A save is one transaction that only succeeds if the stored revision is the one
//!   the new revision follows, so two sessions can't silently overwrite each other.
//! - The vault directory is `0700` and vault files `0600` (Unix); looser permissions
//!   are logged as a warning and the vault still opens.
//! - All statements are parameterized.
//!
//! ```
//! use vault_core::crypto::{self, MasterPassword, Plaintext};
//! use vault_core::storage::{SqliteStore, VaultStore, Vaultname};
//!
//! let dir = tempfile::tempdir()?;
//! let store = SqliteStore::new(dir.path())?;
//! let password = MasterPassword::new("hunter2".into());
//! let (_, sealed) = crypto::create_insecure_for_tests(&password, &Plaintext::new(b"[]".to_vec()))?;
//!
//! let alice = Vaultname::parse("alice")?;
//! store.create(&alice, &sealed)?;
//! assert_eq!(store.load(&alice)?, sealed);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod vaultname;

use std::fmt;
use std::fs::{self, Metadata};
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::config::DbConfig;
use rusqlite::{Connection, ErrorCode, OpenFlags, params};

use crate::crypto::{Header, SealedVault};

pub use vaultname::Vaultname;

/// Marks a SQLite file as a vault file: `SPMV`, the same magic as the vault header.
const APPLICATION_ID: i32 = 0x5350_4D56;

/// Version of the SQL schema below, stored as `user_version`. Independent of the
/// header's format version, which belongs to crypto.
const SCHEMA_VERSION: i32 = 1;

/// The whole schema: exactly one row per vault file.
const SCHEMA: &str = "CREATE TABLE vault (
    id       INTEGER PRIMARY KEY CHECK (id = 1),
    revision INTEGER NOT NULL,
    header   BLOB    NOT NULL,
    body     BLOB    NOT NULL
) STRICT;";

/// File extension of vault files.
const EXTENSION: &str = "vault";

/// How long a save waits for another session's write to finish before failing.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Why a storage operation failed. Messages are fixed strings: they never carry paths,
/// SQLite messages or file contents.
///
/// ```
/// use vault_core::storage::StorageError;
/// assert_eq!(StorageError::NotFound.to_string(), "vault not found");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageError {
    /// The vaultname breaks the allowlist (see [`Vaultname`]).
    InvalidVaultname,
    /// No vault file exists for this vaultname. The session must report this exactly
    /// like a wrong master password, so vaultnames can't be probed.
    NotFound,
    /// `create` was asked for a vaultname that already has a vault file.
    AlreadyExists,
    /// The save doesn't follow the stored revision: another session saved first.
    Conflict,
    /// The file isn't a vault file this build can read: not SQLite, another SQLite
    /// database, an unknown schema version, or a malformed or inconsistent row.
    NotAVault,
    /// The file system or SQLite failed.
    Io,
}

impl fmt::Display for StorageError {
    /// Writes the fixed message for this error.
    ///
    /// ```
    /// # use vault_core::storage::StorageError;
    /// assert_eq!(StorageError::NotAVault.to_string(), "not a vault file");
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidVaultname => {
                "invalid vaultname: use 1-32 letters, digits, '-' or '_', starting with a letter or digit"
            }
            Self::NotFound => "vault not found",
            Self::AlreadyExists => "a vault with this vaultname already exists",
            Self::Conflict => "vault was changed by another session",
            Self::NotAVault => "not a vault file",
            Self::Io => "vault storage failed",
        })
    }
}

impl std::error::Error for StorageError {}

/// Where sealed vaults are kept. The session only ever passes the vaultname it
/// unlocked, so one session can't reach another vault (ADR-0001).
///
/// ```
/// # use vault_core::crypto::{self, MasterPassword, Plaintext};
/// use vault_core::storage::{SqliteStore, VaultStore, Vaultname};
///
/// /// Works with any backend.
/// fn revision_of(store: &impl VaultStore, name: &Vaultname) -> u64 {
///     store.load(name).map(|sealed| sealed.header.revision()).unwrap_or(0)
/// }
/// # let dir = tempfile::tempdir()?;
/// # let store = SqliteStore::new(dir.path())?;
/// # assert_eq!(revision_of(&store, &Vaultname::parse("alice")?), 0);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub trait VaultStore {
    /// Stores a new vault under `name`, failing with [`StorageError::AlreadyExists`]
    /// if one exists. Either the whole vault appears under `name` or nothing does.
    ///
    /// ```
    /// # use vault_core::crypto::{self, MasterPassword, Plaintext};
    /// # use vault_core::storage::{SqliteStore, StorageError, VaultStore, Vaultname};
    /// # let dir = tempfile::tempdir()?;
    /// # let store = SqliteStore::new(dir.path())?;
    /// # let (_, sealed) = crypto::create_insecure_for_tests(&MasterPassword::new("pw".into()), &Plaintext::new(vec![]))?;
    /// let alice = Vaultname::parse("alice")?;
    /// store.create(&alice, &sealed)?;
    /// assert_eq!(store.create(&alice, &sealed), Err(StorageError::AlreadyExists));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn create(&self, name: &Vaultname, sealed: &SealedVault) -> Result<(), StorageError>;

    /// Reads the vault stored under `name`. The header is parsed strictly; the body is
    /// returned as stored and only authenticated later, by crypto.
    ///
    /// ```
    /// # use vault_core::crypto::{self, MasterPassword, Plaintext};
    /// # use vault_core::storage::{SqliteStore, StorageError, VaultStore, Vaultname};
    /// # let dir = tempfile::tempdir()?;
    /// # let store = SqliteStore::new(dir.path())?;
    /// assert_eq!(store.load(&Vaultname::parse("nobody")?), Err(StorageError::NotFound));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn load(&self, name: &Vaultname) -> Result<SealedVault, StorageError>;

    /// Replaces the vault stored under `name` with `sealed`, atomically. Succeeds only
    /// if `sealed` is the revision right after the stored one; otherwise
    /// [`StorageError::Conflict`] and nothing changes.
    ///
    /// ```
    /// # use vault_core::crypto::{self, MasterPassword, Plaintext};
    /// # use vault_core::storage::{SqliteStore, StorageError, VaultStore, Vaultname};
    /// # let dir = tempfile::tempdir()?;
    /// # let store = SqliteStore::new(dir.path())?;
    /// # let alice = Vaultname::parse("alice")?;
    /// # let (key, v0) = crypto::create_insecure_for_tests(&MasterPassword::new("pw".into()), &Plaintext::new(vec![]))?;
    /// # store.create(&alice, &v0)?;
    /// let v1 = crypto::seal(&key, &v0.header, &Plaintext::new(b"[]".to_vec()))?;
    /// store.save(&alice, &v1)?;
    /// assert_eq!(store.save(&alice, &v1), Err(StorageError::Conflict));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn save(&self, name: &Vaultname, sealed: &SealedVault) -> Result<(), StorageError>;
}

/// Vault files as SQLite databases in one vault directory (ADR-0006). Every call opens
/// its own connection and closes it before returning, so nothing holds the file while a
/// session is idle.
///
/// ```
/// use vault_core::storage::SqliteStore;
///
/// let dir = tempfile::tempdir()?;
/// let store = SqliteStore::new(dir.path().join("vaults"))?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct SqliteStore {
    dir: PathBuf,
}

impl SqliteStore {
    /// A store in the vault directory `dir`, creating it (and its parents) if needed.
    /// The front end picks the directory; storage never guesses one.
    ///
    /// Security: a new directory is created `0700` (Unix). An existing one that is
    /// group- or world-writable is logged as a warning, not refused.
    ///
    /// ```
    /// # use vault_core::storage::SqliteStore;
    /// let dir = tempfile::tempdir()?;
    /// let store = SqliteStore::new(dir.path().join("vaults"))?;
    /// assert!(dir.path().join("vaults").is_dir());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self, StorageError> {
        let dir = dir.into();
        create_private_dir(&dir).map_err(io_error)?;
        let metadata = fs::metadata(&dir).map_err(io_error)?;
        if !metadata.is_dir() {
            return Err(StorageError::Io);
        }
        if is_loosely_permitted(&metadata) {
            tracing::warn!(event = "vault_directory_permissions_loose");
        }
        Ok(Self { dir })
    }

    /// The path of `name`'s vault file. The only place a path is built from a vaultname.
    ///
    /// ```ignore
    /// assert!(store.path(&alice).ends_with("alice.vault"));
    /// ```
    fn path(&self, name: &Vaultname) -> PathBuf {
        self.dir.join(format!("{name}.{EXTENSION}"))
    }

    /// Opens `name`'s existing vault file as a hardened connection, after checking it is
    /// a regular file holding a vault schema this build knows.
    ///
    /// Security: symlinks and directories are refused as [`StorageError::NotAVault`];
    /// SQLite's own defences are on before it reads the file.
    ///
    /// ```ignore
    /// let conn = self.open_existing(&alice)?;
    /// ```
    fn open_existing(&self, name: &Vaultname) -> Result<Connection, StorageError> {
        let path = self.path(name);
        let metadata = match fs::symlink_metadata(&path) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Err(StorageError::NotFound);
            }
            result => result.map_err(io_error)?,
        };
        if !metadata.is_file() {
            return Err(StorageError::NotAVault);
        }
        if is_loosely_permitted(&metadata) {
            tracing::warn!(event = "vault_file_permissions_loose", vaultname = %name);
        }
        let conn = open_hardened(&path)?;
        check_vault_schema(&conn)?;
        configure_writes(&conn)?;
        Ok(conn)
    }
}

impl VaultStore for SqliteStore {
    /// Builds the vault in a private temp file in the vault directory, then hard-links
    /// it to its final name, which fails if the name is taken. A crash leaves at most a
    /// stray temp file, never a half-made vault under `name`.
    ///
    /// ```
    /// # use vault_core::crypto::{self, MasterPassword, Plaintext};
    /// # use vault_core::storage::{SqliteStore, VaultStore, Vaultname};
    /// # let dir = tempfile::tempdir()?;
    /// # let store = SqliteStore::new(dir.path())?;
    /// # let (_, sealed) = crypto::create_insecure_for_tests(&MasterPassword::new("pw".into()), &Plaintext::new(vec![]))?;
    /// store.create(&Vaultname::parse("alice")?, &sealed)?;
    /// assert!(dir.path().join("alice.vault").is_file());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn create(&self, name: &Vaultname, sealed: &SealedVault) -> Result<(), StorageError> {
        let revision = sql_revision(sealed.header.revision()).ok_or(StorageError::Io)?;
        // `tempfile` creates the file 0600 on Unix.
        let temp = tempfile::Builder::new()
            .prefix(".")
            .suffix(&format!(".{EXTENSION}.tmp"))
            .tempfile_in(&self.dir)
            .map_err(io_error)?;

        let mut conn = open_hardened(temp.path())?;
        configure_writes(&conn)?;
        let tx = conn.transaction().map_err(sqlite_error)?;
        tx.pragma_update(None, "application_id", APPLICATION_ID)
            .map_err(sqlite_error)?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)
            .map_err(sqlite_error)?;
        tx.execute_batch(SCHEMA).map_err(sqlite_error)?;
        tx.execute(
            "INSERT INTO vault (id, revision, header, body) VALUES (1, ?1, ?2, ?3)",
            params![revision, sealed.header.encode(), sealed.body],
        )
        .map_err(sqlite_error)?;
        tx.commit().map_err(sqlite_error)?;
        conn.close().map_err(|(_, err)| sqlite_error(err))?;

        fs::hard_link(temp.path(), self.path(name)).map_err(|err| {
            if err.kind() == io::ErrorKind::AlreadyExists {
                StorageError::AlreadyExists
            } else {
                StorageError::Io
            }
        })?;
        sync_dir(&self.dir).map_err(io_error)
        // Dropping `temp` removes the temp name; the vault keeps its final one.
    }

    /// Reads the single row, parses the header and checks it agrees with the stored
    /// revision.
    ///
    /// ```
    /// # use vault_core::crypto::{self, MasterPassword, Plaintext};
    /// # use vault_core::storage::{SqliteStore, VaultStore, Vaultname};
    /// # let dir = tempfile::tempdir()?;
    /// # let store = SqliteStore::new(dir.path())?;
    /// # let alice = Vaultname::parse("alice")?;
    /// # let (_, sealed) = crypto::create_insecure_for_tests(&MasterPassword::new("pw".into()), &Plaintext::new(vec![]))?;
    /// # store.create(&alice, &sealed)?;
    /// assert_eq!(store.load(&alice)?.header.revision(), 0);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn load(&self, name: &Vaultname) -> Result<SealedVault, StorageError> {
        let conn = self.open_existing(name)?;
        let (revision, header, body): (i64, Vec<u8>, Vec<u8>) = conn
            .query_row(
                "SELECT revision, header, body FROM vault WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(sqlite_error)?;
        let header = Header::decode(&header).map_err(|_| StorageError::NotAVault)?;
        if sql_revision(header.revision()) != Some(revision) {
            return Err(StorageError::NotAVault);
        }
        Ok(SealedVault { header, body })
    }

    /// One `UPDATE` (a single SQLite transaction) that only matches if the stored
    /// revision is the one before `sealed`'s.
    ///
    /// ```
    /// # use vault_core::crypto::{self, MasterPassword, Plaintext};
    /// # use vault_core::storage::{SqliteStore, VaultStore, Vaultname};
    /// # let dir = tempfile::tempdir()?;
    /// # let store = SqliteStore::new(dir.path())?;
    /// # let alice = Vaultname::parse("alice")?;
    /// # let (key, v0) = crypto::create_insecure_for_tests(&MasterPassword::new("pw".into()), &Plaintext::new(vec![]))?;
    /// # store.create(&alice, &v0)?;
    /// let v1 = crypto::seal(&key, &v0.header, &Plaintext::new(b"[]".to_vec()))?;
    /// store.save(&alice, &v1)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn save(&self, name: &Vaultname, sealed: &SealedVault) -> Result<(), StorageError> {
        let conn = self.open_existing(name)?;
        let new = sealed.header.revision();
        // No stored revision can precede revision 0 or one beyond SQLite's range.
        let (Some(new_sql), Some(expected)) =
            (sql_revision(new), new.checked_sub(1).and_then(sql_revision))
        else {
            return Err(StorageError::Conflict);
        };
        let changed = conn
            .execute(
                "UPDATE vault SET revision = ?1, header = ?2, body = ?3
                 WHERE id = 1 AND revision = ?4",
                params![new_sql, sealed.header.encode(), sealed.body, expected],
            )
            .map_err(sqlite_error)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(StorageError::Conflict)
        }
    }
}

/// Opens `path` as an existing SQLite file (never creating it) with the defences for
/// untrusted files on before the first read: defensive mode, untrusted schema, no URI
/// parsing.
///
/// ```ignore
/// let conn = open_hardened(&path)?;
/// ```
fn open_hardened(path: &Path) -> Result<Connection, StorageError> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(sqlite_error)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(sqlite_error)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)
        .map_err(sqlite_error)?;
    conn.busy_timeout(BUSY_TIMEOUT).map_err(sqlite_error)?;
    Ok(conn)
}

/// Refuses any file whose `application_id` or `user_version` isn't ours, before a
/// table is queried.
///
/// ```ignore
/// check_vault_schema(&conn)?;
/// ```
fn check_vault_schema(conn: &Connection) -> Result<(), StorageError> {
    let read = |pragma| {
        conn.pragma_query_value(None, pragma, |row| row.get::<_, i32>(0))
            .map_err(sqlite_error)
    };
    if read("application_id")? == APPLICATION_ID && read("user_version")? == SCHEMA_VERSION {
        Ok(())
    } else {
        Err(StorageError::NotAVault)
    }
}

/// Sets how writes reach the disk: freed pages zeroed (`secure_delete`), a rollback
/// journal that is deleted after each commit so the vault stays one file, and a full
/// fsync per commit.
///
/// ```ignore
/// configure_writes(&conn)?;
/// ```
fn configure_writes(conn: &Connection) -> Result<(), StorageError> {
    let secure_delete: i64 = conn
        .pragma_update_and_check(None, "secure_delete", true, |row| row.get(0))
        .map_err(sqlite_error)?;
    let journal_mode: String = conn
        .pragma_update_and_check(None, "journal_mode", "DELETE", |row| row.get(0))
        .map_err(sqlite_error)?;
    conn.pragma_update(None, "synchronous", "FULL")
        .map_err(sqlite_error)?;
    if secure_delete == 1 && journal_mode.eq_ignore_ascii_case("delete") {
        Ok(())
    } else {
        Err(StorageError::Io)
    }
}

/// A header revision as SQLite's signed integer; `None` beyond `i64::MAX`.
///
/// ```ignore
/// assert_eq!(sql_revision(1), Some(1));
/// ```
fn sql_revision(revision: u64) -> Option<i64> {
    i64::try_from(revision).ok()
}

/// Maps a SQLite error to a storage error: anything that means "this file isn't a
/// valid vault" becomes [`StorageError::NotAVault`], the rest [`StorageError::Io`].
/// The SQLite message is dropped.
///
/// ```ignore
/// conn.query_row(...).map_err(sqlite_error)?;
/// ```
fn sqlite_error(err: rusqlite::Error) -> StorageError {
    use rusqlite::Error as E;
    match err {
        E::QueryReturnedNoRows | E::InvalidColumnType(..) | E::FromSqlConversionFailure(..) => {
            StorageError::NotAVault
        }
        // `Unknown` is SQLITE_ERROR, e.g. a missing table or column.
        _ if matches!(
            err.sqlite_error_code(),
            Some(ErrorCode::NotADatabase | ErrorCode::DatabaseCorrupt | ErrorCode::Unknown)
        ) =>
        {
            StorageError::NotAVault
        }
        _ => StorageError::Io,
    }
}

/// Maps a file system error to [`StorageError::Io`], dropping its message (which may
/// contain a path).
///
/// ```ignore
/// fs::metadata(&dir).map_err(io_error)?;
/// ```
fn io_error(_: io::Error) -> StorageError {
    StorageError::Io
}

/// Creates `dir` and any missing parents, `0700` on Unix. An existing directory is
/// left as it is.
///
/// ```ignore
/// create_private_dir(Path::new("/home/alice/.local/share/secure-pass-manager/vaults"))?;
/// ```
fn create_private_dir(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)
}

/// Whether other users may write to this file or directory (group- or world-writable).
/// Always `false` off Unix, where there are no mode bits to check.
///
/// ```ignore
/// if is_loosely_permitted(&metadata) { tracing::warn!(...) }
/// ```
fn is_loosely_permitted(metadata: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o022 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}

/// Makes a new directory entry (the vault's final name) durable by fsyncing the
/// directory. A no-op off Unix, where directories can't be opened for syncing.
///
/// ```ignore
/// sync_dir(&self.dir)?;
/// ```
fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    fs::File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}
