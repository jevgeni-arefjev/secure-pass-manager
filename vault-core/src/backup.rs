//! Backup module: ciphertext-only copies of a vault file.
//!
//! A backup is the vault file exactly as stored (`header ‖ body`), written to a path the
//! owner chooses outside the vault directory. Nothing is decrypted or re-encrypted, and
//! the audit log is not copied (ADR-0010). It is restored by hand: create a vault home
//! and put the backup in it as `secrets.vault` (ADR-0009); any vaultname works
//! (ADR-0004). Front ends make backups through [`crate::session::Session::backup`],
//! which checks the copy against the session's vault key before it is put in place.
//!
//! Security:
//! - Never overwrites: the destination must not exist (not even as a symlink), and the
//!   final rename refuses an existing target, so a file created meanwhile is kept.
//! - The destination's directory must already exist and must not be inside the vault
//!   directory, so a backup can't be mistaken for, or turned into, a vault home.
//! - The backup is built in a `0600` temp file next to the destination, fsynced, read
//!   back and verified, and only then renamed into place: a failure or crash leaves
//!   nothing at the destination, at most a stray `.vault-backup-*.tmp` holding
//!   ciphertext.
//! - Errors are fixed strings; they never carry a path.
//!
//! ```
//! use vault_core::backup::{BackupError, Destination};
//!
//! let vaults = tempfile::tempdir()?;
//! let elsewhere = tempfile::tempdir()?;
//! Destination::new(&elsewhere.path().join("alice.vault"), vaults.path())?;
//! assert_eq!(
//!     Destination::new(&vaults.path().join("alice.vault"), vaults.path()).err(),
//!     Some(BackupError::InsideVaultDirectory),
//! );
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use tempfile::NamedTempFile;

use crate::crypto::SealedVault;
use crate::storage;

/// Prefix of the temp file a backup is built in (`.vault-backup-<random>.tmp`).
const TEMP_PREFIX: &str = ".vault-backup-";

/// Why a backup failed. Messages are fixed strings: they never carry a path or an OS
/// message.
///
/// ```
/// use vault_core::backup::BackupError;
/// assert_eq!(
///     BackupError::Exists.to_string(),
///     "something already exists at the backup path; a backup never overwrites"
/// );
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackupError {
    /// The path doesn't name a file (e.g. it is empty, `/` or ends in `..` or `/`).
    NotAFilePath,
    /// The directory the backup would go in doesn't exist or isn't a directory.
    NoDirectory,
    /// The path is inside the vault directory.
    InsideVaultDirectory,
    /// Something (a file, directory or symlink) already exists at the path.
    Exists,
    /// The written copy didn't read back as the vault, or didn't open with the
    /// session's vault key. Nothing was put at the path.
    Unverified,
    /// The file system failed, with the [`io::ErrorKind`] it failed with (never the OS
    /// message, which can carry the path).
    Io(io::ErrorKind),
}

impl fmt::Display for BackupError {
    /// Writes the fixed message for this error.
    ///
    /// ```
    /// # use vault_core::backup::BackupError;
    /// assert_eq!(
    ///     BackupError::Io(std::io::ErrorKind::StorageFull).to_string(),
    ///     "backup could not be written"
    /// );
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotAFilePath => "the backup path must name a file",
            Self::NoDirectory => "the backup path's directory doesn't exist",
            Self::InsideVaultDirectory => "a backup can't be written inside the vault directory",
            Self::Exists => {
                "something already exists at the backup path; a backup never overwrites"
            }
            Self::Unverified => "the backup didn't verify; nothing was written",
            Self::Io(_) => "backup could not be written",
        })
    }
}

impl std::error::Error for BackupError {}

/// A checked place to write a backup: a file name that is free, in an existing
/// directory outside the vault directory. Checking again at write time is left to the
/// final rename, which refuses an existing target.
///
/// ```
/// use vault_core::backup::{BackupError, Destination};
///
/// let vaults = tempfile::tempdir()?;
/// let elsewhere = tempfile::tempdir()?;
/// let taken = elsewhere.path().join("taken.vault");
/// std::fs::write(&taken, b"")?;
/// assert_eq!(Destination::new(&taken, vaults.path()).err(), Some(BackupError::Exists));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct Destination {
    /// The destination's directory, with symlinks resolved.
    dir: PathBuf,
    /// `dir` joined with the destination's file name.
    path: PathBuf,
}

impl Destination {
    /// Checks `path` as a backup destination for vaults kept in `vault_dir`. A relative
    /// `path` is taken from the current directory.
    ///
    /// Security: the directory is resolved (symlinks followed) before it is compared
    /// with the resolved vault directory, so a symlinked path can't sneak a backup into
    /// it. The final component is never followed: a symlink there counts as
    /// [`BackupError::Exists`].
    ///
    /// ```
    /// # use vault_core::backup::{BackupError, Destination};
    /// let vaults = tempfile::tempdir()?;
    /// let elsewhere = tempfile::tempdir()?;
    /// let missing = elsewhere.path().join("no/such/dir/alice.vault");
    /// assert_eq!(Destination::new(&missing, vaults.path()).err(), Some(BackupError::NoDirectory));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new(path: &Path, vault_dir: &Path) -> Result<Self, BackupError> {
        let ends_in_separator = path
            .as_os_str()
            .to_string_lossy()
            .ends_with(std::path::is_separator);
        let name = match path.file_name() {
            Some(name) if !ends_in_separator => name,
            _ => return Err(BackupError::NotAFilePath),
        };
        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        let dir = match fs::canonicalize(parent) {
            Ok(dir) if dir.is_dir() => dir,
            Ok(_) => return Err(BackupError::NoDirectory),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Err(BackupError::NoDirectory);
            }
            Err(err) => return Err(BackupError::Io(err.kind())),
        };
        let vault_dir = fs::canonicalize(vault_dir).map_err(|err| BackupError::Io(err.kind()))?;
        if dir.starts_with(&vault_dir) {
            return Err(BackupError::InsideVaultDirectory);
        }
        let path = dir.join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => Err(BackupError::Exists),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Self { dir, path }),
            Err(err) => Err(BackupError::Io(err.kind())),
        }
    }
}

/// A backup written to a temp file next to its destination but not yet in place.
/// Dropping it removes the temp file, so an unverified backup never appears.
///
/// ```ignore
/// let staged = backup::stage(&dest, &sealed)?;
/// assert_eq!(staged.read_back()?, sealed);
/// staged.commit()?;
/// ```
pub(crate) struct Staged {
    /// The temp file in the destination's directory holding the copy until it is committed.
    temp: NamedTempFile,
    /// Where the copy goes once it is read back and verified.
    dest: Destination,
}

/// Writes `sealed` to a fsynced `0600` temp file in `dest`'s directory.
///
/// ```ignore
/// let staged = backup::stage(&dest, &sealed)?;
/// ```
pub(crate) fn stage(dest: &Destination, sealed: &SealedVault) -> Result<Staged, BackupError> {
    let temp = storage::write_temp_named(&dest.dir, TEMP_PREFIX, sealed)
        .map_err(|err| BackupError::Io(err.kind()))?;
    Ok(Staged {
        temp,
        dest: dest.clone(),
    })
}

impl Staged {
    /// Reads the staged file back from disk exactly as storage reads a vault file, so
    /// the caller can check it before [`Staged::commit`].
    ///
    /// ```ignore
    /// let copy = staged.read_back()?;
    /// ```
    pub(crate) fn read_back(&self) -> Result<SealedVault, BackupError> {
        let (file, _) =
            storage::open_vault_file_at(self.temp.path()).map_err(|_| BackupError::Unverified)?;
        storage::read_sealed(file).map_err(|_| BackupError::Unverified)
    }

    /// Renames the staged file to the destination, refusing an existing target, then
    /// fsyncs the directory. Once the rename is done the backup exists and this returns
    /// `Ok`, even if the directory fsync fails (logged as a warning).
    ///
    /// ```ignore
    /// staged.commit()?;
    /// ```
    pub(crate) fn commit(self) -> Result<(), BackupError> {
        self.temp
            .persist_noclobber(&self.dest.path)
            .map_err(|err| match err.error.kind() {
                io::ErrorKind::AlreadyExists => BackupError::Exists,
                kind => BackupError::Io(kind),
            })?;
        storage::sync_dir_after_commit(&self.dest.dir);
        Ok(())
    }
}

/// A backup handed out whole instead of written to a [`Destination`], e.g. for a
/// browser to download: the vault file's bytes (`header ‖ body`) exactly as stored,
/// and the revision they hold. Made by
/// [`crate::session::Session::backup_file`], which checks them first.
///
/// Security: ciphertext only, like any backup; nothing in it is decrypted.
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
/// let file = session.backup_file()?;
/// assert_eq!(file.revision(), 0);
/// assert!(!file.bytes().is_empty());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct BackupFile {
    /// The revision of the vault the backup holds.
    revision: u64,
    /// The vault file's bytes.
    bytes: Vec<u8>,
}

impl BackupFile {
    /// The backup of `sealed`: its header encoded as storage writes it, then its body.
    ///
    /// ```ignore
    /// let file = BackupFile::of(&stored);
    /// ```
    pub(crate) fn of(sealed: &SealedVault) -> Self {
        let mut bytes = sealed.header.encode();
        bytes.extend_from_slice(&sealed.body);
        Self {
            revision: sealed.header.revision(),
            bytes,
        }
    }

    /// The revision of the vault the backup holds.
    ///
    /// ```ignore
    /// let name = format!("alice-r{}.vault", file.revision());
    /// ```
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// The vault file's bytes, to save as a vault home's `secrets.vault` on restore.
    ///
    /// ```ignore
    /// std::fs::write(home.join("secrets.vault"), file.bytes())?;
    /// ```
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for BackupFile {
    /// Shows the revision and size only.
    ///
    /// ```ignore
    /// println!("{file:?}"); // BackupFile { revision: 3, len: 1234 }
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackupFile")
            .field("revision", &self.revision)
            .field("len", &self.bytes.len())
            .finish()
    }
}
