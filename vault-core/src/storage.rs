//! Storage module: vault files on disk.
//!
//! Each vault has a vault home, `<vault directory>/<vaultname>/` (ADR-0009), holding its
//! vault file `secrets.vault`: the encoded header followed by the encrypted body, with
//! no container around them (ADR-0011). Storage only ever handles what crypto sealed
//! ([`SealedVault`]); it never sees plaintext or keys.
//!
//! Security:
//! - Vaultnames are allowlisted by [`Vaultname`] before they become directory names;
//!   a vault home that is a symlink or not a directory is refused.
//! - Vault files may come from untrusted places, so the only parser they meet is the
//!   strict [`Header::decode`]; there is no query language to inject into.
//! - Every write goes to a temp file that is fsynced, then renamed (or, on create,
//!   hard-linked) into place, so a crash leaves the old vault or the new one, never a
//!   mix, and the vault file never keeps old ciphertext. Temp files a crash leaves
//!   behind are removed by the next save.
//! - A vault file over 64 MiB is refused before it is read, so it can't exhaust memory.
//! - A save holds an exclusive lock on `secrets.lock` and only succeeds if the stored
//!   revision is the one the new revision follows, so two sessions can't silently
//!   overwrite each other.
//! - Vault and lock files are opened without following symlinks. The vault directory
//!   and vault homes are `0700`, vault and lock files `0600` (Unix); a directory others
//!   can write to, or a file others can read or write, is logged as a warning and the
//!   vault still opens.
//!
//! ```
//! use vault_core::crypto::{self, MasterPassword, Plaintext};
//! use vault_core::storage::{FileStore, VaultStore, Vaultname};
//!
//! let dir = tempfile::tempdir()?;
//! let store = FileStore::new(dir.path())?;
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
use std::fs::{self, File, Metadata, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::NamedTempFile;

use crate::crypto::{Header, SealedVault};

pub use vaultname::Vaultname;

/// Name of the vault file inside a vault home (ADR-0009). Fixed, so the vault home's
/// name is the only place the vaultname lives.
const VAULT_FILE: &str = "secrets.vault";

/// Name of the empty file a save locks while it checks the revision and replaces the
/// vault file (ADR-0011). The vault file itself can't be locked: the rename replaces it.
const LOCK_FILE: &str = "secrets.lock";

/// Largest vault file, in bytes, header included. Far above any real vault (a few KiB).
///
/// Security: one limit for both directions. Loading refuses a larger file, so a planted
/// or corrupted one can't exhaust memory; saving refuses to write one
/// ([`StorageError::VaultFull`]), so a vault can never grow too large to open again.
pub const MAX_VAULT_FILE_LEN: u64 = 64 * 1024 * 1024;

/// Prefix of the temp files a write builds a vault in (`.<random>.tmp`).
const TEMP_PREFIX: &str = ".";
/// Suffix of those temp files.
const TEMP_SUFFIX: &str = ".tmp";

/// How long a save waits for another session's save to finish before failing.
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a waiting save sleeps between attempts to take the lock.
const LOCK_RETRY: Duration = Duration::from_millis(10);

/// Why a storage operation failed. Messages are fixed strings: they never carry paths,
/// OS messages or file contents.
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
    /// The file isn't a vault file this build can read: not a regular file, shorter
    /// than a header, over the size limit, or a header with the wrong magic or an
    /// unknown format version.
    NotAVault,
    /// Writing would make the vault file larger than [`MAX_VAULT_FILE_LEN`], so it
    /// couldn't be opened again. Nothing was written.
    VaultFull,
    /// The file system failed, with the [`io::ErrorKind`] it failed with (never the OS
    /// message, which can carry a path). Another session holding the lock for longer
    /// than a save waits is [`io::ErrorKind::TimedOut`] ([`LOCK_HELD_TOO_LONG`]).
    Io(io::ErrorKind),
}

/// The cause kind of a save that gave up waiting for another session's lock.
///
/// ```
/// use vault_core::storage::{LOCK_HELD_TOO_LONG, StorageError};
/// let busy = StorageError::Io(LOCK_HELD_TOO_LONG);
/// assert_eq!(busy.to_string(), "vault storage failed");
/// ```
pub const LOCK_HELD_TOO_LONG: io::ErrorKind = io::ErrorKind::TimedOut;

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
            Self::VaultFull => "vault is full",
            Self::Io(_) => "vault storage failed",
        })
    }
}

impl std::error::Error for StorageError {}

/// Where sealed vaults are kept. The session only ever passes the vaultname it
/// unlocked, so one session can't reach another vault (ADR-0001).
///
/// ```
/// # use vault_core::crypto::{self, MasterPassword, Plaintext};
/// use vault_core::storage::{FileStore, VaultStore, Vaultname};
///
/// /// Works with any backend.
/// fn revision_of(store: &impl VaultStore, name: &Vaultname) -> u64 {
///     store.load(name).map(|sealed| sealed.header.revision()).unwrap_or(0)
/// }
/// # let dir = tempfile::tempdir()?;
/// # let store = FileStore::new(dir.path())?;
/// # assert_eq!(revision_of(&store, &Vaultname::parse("alice")?), 0);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub trait VaultStore {
    /// Stores a new vault under `name`, failing with [`StorageError::AlreadyExists`]
    /// if one exists. Either the whole vault appears under `name` or nothing does.
    ///
    /// ```
    /// # use vault_core::crypto::{self, MasterPassword, Plaintext};
    /// # use vault_core::storage::{FileStore, StorageError, VaultStore, Vaultname};
    /// # let dir = tempfile::tempdir()?;
    /// # let store = FileStore::new(dir.path())?;
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
    /// # use vault_core::storage::{FileStore, StorageError, VaultStore, Vaultname};
    /// # let dir = tempfile::tempdir()?;
    /// # let store = FileStore::new(dir.path())?;
    /// assert_eq!(store.load(&Vaultname::parse("nobody")?), Err(StorageError::NotFound));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn load(&self, name: &Vaultname) -> Result<SealedVault, StorageError>;

    /// Replaces the vault stored under `name` with `sealed`, atomically. Succeeds only
    /// if `sealed` is the revision right after the stored one; otherwise
    /// [`StorageError::Conflict`] and nothing changes. A `sealed` too large to load
    /// again ([`MAX_VAULT_FILE_LEN`]) is refused as [`StorageError::VaultFull`], also
    /// changing nothing; `create` refuses it the same way.
    ///
    /// ```
    /// # use vault_core::crypto::{self, MasterPassword, Plaintext};
    /// # use vault_core::storage::{FileStore, StorageError, VaultStore, Vaultname};
    /// # let dir = tempfile::tempdir()?;
    /// # let store = FileStore::new(dir.path())?;
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

/// Vault files as flat `header ‖ body` files in one vault directory (ADR-0011). Every
/// call opens the files it needs and closes them before returning, so nothing holds a
/// vault file while a session is idle.
///
/// ```
/// use vault_core::storage::FileStore;
///
/// let dir = tempfile::tempdir()?;
/// let store = FileStore::new(dir.path().join("vaults"))?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct FileStore {
    /// Vault directory holding one vault home per vaultname.
    dir: PathBuf,
}

impl FileStore {
    /// A store in the vault directory `dir`, creating it (and its parents) if needed.
    /// The front end picks the directory; storage never guesses one.
    ///
    /// Security: a new directory is created `0700` (Unix). An existing one that is
    /// group- or world-writable is logged as a warning, not refused.
    ///
    /// ```
    /// # use vault_core::storage::FileStore;
    /// let dir = tempfile::tempdir()?;
    /// let store = FileStore::new(dir.path().join("vaults"))?;
    /// assert!(dir.path().join("vaults").is_dir());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self, StorageError> {
        let dir = dir.into();
        create_private_dir(&dir).map_err(io_error)?;
        let metadata = fs::metadata(&dir).map_err(io_error)?;
        if !metadata.is_dir() {
            return Err(StorageError::Io(io::ErrorKind::NotADirectory));
        }
        if is_loosely_permitted(&metadata) {
            tracing::warn!(event = "vault_directory_permissions_loose");
        }
        Ok(Self { dir })
    }

    /// The path of `name`'s vault home.
    ///
    /// ```ignore
    /// assert!(store.home(&alice).ends_with("alice"));
    /// ```
    fn home(&self, name: &Vaultname) -> PathBuf {
        vault_home(&self.dir, name)
    }

    /// The path of `name`'s vault file, inside its vault home.
    ///
    /// ```ignore
    /// assert!(store.path(&alice).ends_with("alice/secrets.vault"));
    /// ```
    fn path(&self, name: &Vaultname) -> PathBuf {
        self.home(name).join(VAULT_FILE)
    }

    /// Checks `name`'s vault home; see [`existing_vault_home`].
    ///
    /// ```ignore
    /// self.check_home(&alice)?;
    /// ```
    fn check_home(&self, name: &Vaultname) -> Result<(), StorageError> {
        existing_vault_home(&self.dir, name).map(drop)
    }

    /// Checks that `name`'s vault home and vault file exist and that the vault file is a
    /// regular file, without opening it.
    ///
    /// Security: symlinks, directories and special files (e.g. a FIFO, which would block
    /// a read) are refused as [`StorageError::NotAVault`].
    ///
    /// ```ignore
    /// self.check_vault_file(&alice)?;
    /// ```
    fn check_vault_file(&self, name: &Vaultname) -> Result<(), StorageError> {
        self.check_home(name)?;
        match fs::symlink_metadata(self.path(name)) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => Err(StorageError::NotFound),
            Err(err) => Err(io_error(err)),
            Ok(metadata) if metadata.is_file() => Ok(()),
            Ok(_) => Err(StorageError::NotAVault),
        }
    }

    /// Opens `name`'s vault file for reading, after [`Self::check_vault_file`] has
    /// passed. Call it while holding the lock if what is read decides a save.
    ///
    /// Security: opened with `O_NOFOLLOW` and checked again on the opened file, so it
    /// can't be swapped for a symlink or special file between check and read. A file
    /// over [`MAX_VAULT_FILE_LEN`] is refused as [`StorageError::NotAVault`].
    ///
    /// ```ignore
    /// self.check_vault_file(&alice)?;
    /// let file = self.open_vault_file(&alice)?;
    /// ```
    fn open_vault_file(&self, name: &Vaultname) -> Result<File, StorageError> {
        let (file, metadata) = open_vault_file_at(&self.path(name))?;
        if is_loosely_permitted(&metadata) {
            tracing::warn!(event = "vault_file_permissions_loose", vaultname = %name);
        }
        Ok(file)
    }

    /// Reads and parses `name`'s whole vault file.
    ///
    /// ```ignore
    /// let sealed = self.read_vault(&alice)?;
    /// ```
    fn read_vault(&self, name: &Vaultname) -> Result<SealedVault, StorageError> {
        self.check_vault_file(name)?;
        read_sealed(self.open_vault_file(name)?)
    }

    /// The revision of the vault stored under `name`, read from its header alone. Used
    /// by a save, under the lock, after [`Self::check_vault_file`].
    ///
    /// ```ignore
    /// let stored = self.read_revision(&alice)?;
    /// ```
    fn read_revision(&self, name: &Vaultname) -> Result<u64, StorageError> {
        let mut file = self.open_vault_file(name)?;
        let mut header = [0; Header::LEN];
        file.read_exact(&mut header).map_err(|err| {
            if err.kind() == io::ErrorKind::UnexpectedEof {
                StorageError::NotAVault
            } else {
                io_error(err)
            }
        })?;
        Header::decode(&header)
            .map(|header| header.revision())
            .map_err(|_| StorageError::NotAVault)
    }
}

impl VaultStore for FileStore {
    /// Creates the vault home, writes the vault to a private temp file inside it, then
    /// hard-links it to `secrets.vault`, which fails if a vault is already there. A crash
    /// leaves at most an empty vault home or a stray temp file, never a half-made vault
    /// under `name`; a later `create` takes such a vault home over (ADR-0009).
    ///
    /// ```
    /// # use vault_core::crypto::{self, MasterPassword, Plaintext};
    /// # use vault_core::storage::{FileStore, VaultStore, Vaultname};
    /// # let dir = tempfile::tempdir()?;
    /// # let store = FileStore::new(dir.path())?;
    /// # let (_, sealed) = crypto::create_insecure_for_tests(&MasterPassword::new("pw".into()), &Plaintext::new(vec![]))?;
    /// store.create(&Vaultname::parse("alice")?, &sealed)?;
    /// assert!(dir.path().join("alice/secrets.vault").is_file());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn create(&self, name: &Vaultname, sealed: &SealedVault) -> Result<(), StorageError> {
        check_fits(sealed)?;
        let home = self.home(name);
        create_vault_home(&home).map_err(io_error)?;
        self.check_home(name)?;
        let temp = write_temp(&home, sealed).map_err(io_error)?;
        fs::hard_link(temp.path(), self.path(name)).map_err(|err| {
            if err.kind() == io::ErrorKind::AlreadyExists {
                StorageError::AlreadyExists
            } else {
                io_error(err)
            }
        })?;
        // The vault now exists: from here on, failing would misreport what happened.
        sync_dir_after_commit(&home);
        sync_dir_after_commit(&self.dir);
        Ok(())
        // Dropping `temp` removes the temp name; the vault keeps its final one.
    }

    /// Reads the vault file and splits it into the strictly parsed header and the body.
    ///
    /// ```
    /// # use vault_core::crypto::{self, MasterPassword, Plaintext};
    /// # use vault_core::storage::{FileStore, VaultStore, Vaultname};
    /// # let dir = tempfile::tempdir()?;
    /// # let store = FileStore::new(dir.path())?;
    /// # let alice = Vaultname::parse("alice")?;
    /// # let (_, sealed) = crypto::create_insecure_for_tests(&MasterPassword::new("pw".into()), &Plaintext::new(vec![]))?;
    /// # store.create(&alice, &sealed)?;
    /// assert_eq!(store.load(&alice)?.header.revision(), 0);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn load(&self, name: &Vaultname) -> Result<SealedVault, StorageError> {
        self.read_vault(name)
    }

    /// Under the vault home's lock: reads the stored revision from its header, checks
    /// `sealed` follows it, removes temp files left by interrupted writes, then writes
    /// `sealed` to a temp file and renames it over `secrets.vault`. Once the rename is
    /// done the save has happened and returns `Ok`, even if the directory fsync after it
    /// fails (logged as a warning).
    ///
    /// ```
    /// # use vault_core::crypto::{self, MasterPassword, Plaintext};
    /// # use vault_core::storage::{FileStore, VaultStore, Vaultname};
    /// # let dir = tempfile::tempdir()?;
    /// # let store = FileStore::new(dir.path())?;
    /// # let alice = Vaultname::parse("alice")?;
    /// # let (key, v0) = crypto::create_insecure_for_tests(&MasterPassword::new("pw".into()), &Plaintext::new(vec![]))?;
    /// # store.create(&alice, &v0)?;
    /// let v1 = crypto::seal(&key, &v0.header, &Plaintext::new(b"[]".to_vec()))?;
    /// store.save(&alice, &v1)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn save(&self, name: &Vaultname, sealed: &SealedVault) -> Result<(), StorageError> {
        check_fits(sealed)?;
        // Checked before locking, so a missing vault leaves no lock file behind.
        self.check_vault_file(name)?;
        let home = self.home(name);
        let _lock = lock_vault_home(&home)?;
        let stored = self.read_revision(name)?;
        if sealed.header.revision().checked_sub(1) != Some(stored) {
            return Err(StorageError::Conflict);
        }
        remove_stale_temps(&home);
        let temp = write_temp(&home, sealed).map_err(io_error)?;
        temp.persist(self.path(name))
            .map_err(|err| io_error(err.error))?;
        sync_dir_after_commit(&home);
        Ok(())
    }
}

/// The path of `name`'s vault home in the vault directory `dir`. The only place a path
/// is built from a vaultname.
///
/// ```ignore
/// assert!(vault_home(&dir, &alice).ends_with("alice"));
/// ```
fn vault_home(dir: &Path, name: &Vaultname) -> PathBuf {
    dir.join(name.as_str())
}

/// The path of `name`'s vault home in the vault directory `dir`, after checking it is a
/// real directory, not a symlink or a file; [`StorageError::NotFound`] if it doesn't
/// exist. Never creates it. Also used by the audit log (ADR-0010).
///
/// Security: a symlinked vault home could point one vaultname at another vault or
/// outside the vault directory, so it is refused as [`StorageError::NotAVault`].
/// Group- or world-writable permissions are logged as a warning, not refused.
///
/// ```ignore
/// let home = storage::existing_vault_home(&dir, &alice)?;
/// ```
pub(crate) fn existing_vault_home(dir: &Path, name: &Vaultname) -> Result<PathBuf, StorageError> {
    let home = vault_home(dir, name);
    let metadata = match fs::symlink_metadata(&home) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Err(StorageError::NotFound);
        }
        result => result.map_err(io_error)?,
    };
    if !metadata.is_dir() {
        return Err(StorageError::NotAVault);
    }
    if is_loosely_permitted(&metadata) {
        tracing::warn!(event = "vault_home_permissions_loose", vaultname = %name);
    }
    Ok(home)
}

/// Opens the vault file at `path` for reading and returns it with its metadata. Used
/// for vault files in a vault home and for backups (see [`crate::backup`]).
///
/// Security: opened with `O_NOFOLLOW` and checked on the opened file, so it can't be
/// swapped for a symlink or another special file between check and read; such files
/// and files over [`MAX_VAULT_FILE_LEN`] are refused as [`StorageError::NotAVault`].
/// A FIFO would block the open itself, before that check: callers rule it out first
/// with `symlink_metadata` (only the owner or root could swap one in between).
///
/// ```ignore
/// let (file, metadata) = storage::open_vault_file_at(&path)?;
/// ```
pub(crate) fn open_vault_file_at(path: &Path) -> Result<(File, Metadata), StorageError> {
    let file = match open_no_follow(OpenOptions::new().read(true), path) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Err(StorageError::NotFound);
        }
        result => result.map_err(io_error)?,
    };
    let metadata = file.metadata().map_err(io_error)?;
    if !metadata.is_file() || metadata.len() > MAX_VAULT_FILE_LEN {
        return Err(StorageError::NotAVault);
    }
    Ok((file, metadata))
}

/// Reads the whole vault file `file` (opened by [`open_vault_file_at`]) and splits it
/// into its strictly parsed header and its body.
///
/// ```ignore
/// let (file, _) = storage::open_vault_file_at(&path)?;
/// let sealed = storage::read_sealed(file)?;
/// ```
pub(crate) fn read_sealed(file: File) -> Result<SealedVault, StorageError> {
    let mut bytes = Vec::new();
    // The bound also covers a file that grows after its length was checked.
    file.take(MAX_VAULT_FILE_LEN + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() as u64 > MAX_VAULT_FILE_LEN {
        return Err(StorageError::NotAVault);
    }
    decode_vault(bytes)
}

/// Refuses `sealed` as [`StorageError::VaultFull`] if its file would be larger than
/// [`MAX_VAULT_FILE_LEN`], the most the loader reads back.
///
/// ```ignore
/// check_fits(&sealed)?; // before anything is written
/// ```
fn check_fits(sealed: &SealedVault) -> Result<(), StorageError> {
    let file_len = Header::LEN as u64 + sealed.body.len() as u64;
    if file_len > MAX_VAULT_FILE_LEN {
        return Err(StorageError::VaultFull);
    }
    Ok(())
}

/// Splits the bytes of a vault file into its header and body.
///
/// Security: these bytes are untrusted; [`Header::decode`] is their only parser. The
/// body is returned as stored and only authenticated later, by crypto.
///
/// ```ignore
/// assert_eq!(decode_vault(b"junk".to_vec()), Err(StorageError::NotAVault));
/// ```
fn decode_vault(mut bytes: Vec<u8>) -> Result<SealedVault, StorageError> {
    if bytes.len() < Header::LEN {
        return Err(StorageError::NotAVault);
    }
    let body = bytes.split_off(Header::LEN);
    let header = Header::decode(&bytes).map_err(|_| StorageError::NotAVault)?;
    Ok(SealedVault { header, body })
}

/// Writes `sealed` as `header ‖ body` to a new temp file in the vault home `home` and
/// fsyncs it. The caller links or renames it into place; dropping it removes it.
///
/// Security: `tempfile` creates the file `0600` (Unix) with a random name, so it can't
/// be pre-created or read by others.
///
/// ```ignore
/// let temp = write_temp(&home, &sealed)?;
/// temp.persist(home.join(VAULT_FILE))?;
/// ```
fn write_temp(home: &Path, sealed: &SealedVault) -> io::Result<NamedTempFile> {
    write_temp_named(home, TEMP_PREFIX, sealed)
}

/// Writes `sealed` as `header ‖ body` to a new temp file `<prefix><random>.tmp` in the
/// directory `dir` and fsyncs it, like [`write_temp`]. Backups use their own `prefix`,
/// so a save's cleanup never mistakes one for its own leftovers.
///
/// ```ignore
/// let temp = storage::write_temp_named(&dir, ".vault-backup-", &sealed)?;
/// ```
pub(crate) fn write_temp_named(
    dir: &Path,
    prefix: &str,
    sealed: &SealedVault,
) -> io::Result<NamedTempFile> {
    let mut temp = tempfile::Builder::new()
        .prefix(prefix)
        .suffix(TEMP_SUFFIX)
        .tempfile_in(dir)?;
    temp.write_all(&sealed.header.encode())?;
    temp.write_all(&sealed.body)?;
    temp.as_file().sync_all()?;
    Ok(temp)
}

/// Removes the temp files (`.<random>.tmp`) a crashed write left in the vault home
/// `home`. Best effort: a file that can't be removed is logged and left for next time.
/// Call it only while holding the lock, so no other save's temp file is in flight.
///
/// Security: a leftover temp file holds a whole sealed vault, possibly with a header
/// wrapped under a since-rotated master password. Only regular files are removed; a
/// symlink of that name is left alone.
///
/// ```ignore
/// let _lock = lock_vault_home(&home)?;
/// remove_stale_temps(&home);
/// ```
fn remove_stale_temps(home: &Path) {
    let Ok(entries) = fs::read_dir(home) else {
        tracing::warn!(event = "vault_temp_cleanup_failed");
        return;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        let is_temp = file_name.len() > TEMP_PREFIX.len() + TEMP_SUFFIX.len()
            && file_name.starts_with(TEMP_PREFIX)
            && file_name.ends_with(TEMP_SUFFIX);
        let is_file = entry.file_type().is_ok_and(|kind| kind.is_file());
        if is_temp && is_file && fs::remove_file(entry.path()).is_err() {
            tracing::warn!(event = "vault_temp_cleanup_failed");
        }
    }
}

/// Takes the exclusive lock on the vault home's `secrets.lock`, creating the file if
/// needed, and returns it; the lock is held until the file is dropped. Retries for up
/// to [`LOCK_TIMEOUT`], then fails with [`StorageError::Io`] of [`LOCK_HELD_TOO_LONG`].
///
/// Security: the lock file is created `0600` (Unix) and opened with `O_NOFOLLOW`, so a
/// planted symlink can't make a save create or lock a file elsewhere.
///
/// ```ignore
/// let _lock = lock_vault_home(&home)?;
/// ```
fn lock_vault_home(home: &Path) -> Result<File, StorageError> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(false);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let file = open_no_follow(&options, &home.join(LOCK_FILE)).map_err(io_error)?;
    if !file.metadata().map_err(io_error)?.is_file() {
        return Err(StorageError::Io(io::ErrorKind::InvalidInput));
    }
    let deadline = Instant::now() + LOCK_TIMEOUT;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                thread::sleep(LOCK_RETRY);
            }
            Err(TryLockError::WouldBlock) => return Err(StorageError::Io(LOCK_HELD_TOO_LONG)),
            Err(TryLockError::Error(err)) => return Err(io_error(err)),
        }
    }
}

/// Opens `path` with `options`, never following a symlink (`O_NOFOLLOW` on Unix; a
/// plain open elsewhere). The one place that flag is set; the audit log uses it too.
///
/// ```ignore
/// let file = open_no_follow(OpenOptions::new().read(true), &path)?;
/// ```
pub(crate) fn open_no_follow(options: &OpenOptions, path: &Path) -> io::Result<File> {
    let mut options = options.clone();
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NOFOLLOW);
    options.open(path)
}

/// Maps a file system error to [`StorageError::Io`], keeping only its kind and
/// dropping its message (which may contain a path).
///
/// ```ignore
/// fs::metadata(&dir).map_err(io_error)?;
/// ```
pub(crate) fn io_error(err: io::Error) -> StorageError {
    StorageError::Io(err.kind())
}

/// Creates `dir` and any missing parents, `0700` on Unix. An existing directory is
/// left as it is.
///
/// ```ignore
/// create_private_dir(Path::new("/home/alice/.local/share/secure-pass-manager/vaults"))?;
/// ```
fn create_private_dir(dir: &Path) -> io::Result<()> {
    private_dir_builder().recursive(true).create(dir)
}

/// A directory builder that creates directories `0700` on Unix: the one place that
/// mode is set.
///
/// ```ignore
/// private_dir_builder().create(home)?;
/// ```
fn private_dir_builder() -> fs::DirBuilder {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
}

/// Creates the vault home `home`, `0700` on Unix. One left behind by an interrupted
/// `create` is reused; the hard link to `secrets.vault` still refuses a taken vaultname.
///
/// ```ignore
/// create_vault_home(&store.home(&alice))?;
/// ```
fn create_vault_home(home: &Path) -> io::Result<()> {
    match private_dir_builder().create(home) {
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        result => result,
    }
}

/// Whether other users may write to this directory, or read or write this file (group
/// or other bits). A readable file matters too: the audit log holds titles in
/// plaintext, and a readable vault file can be copied for offline guessing. A readable
/// directory only shows names (vaultnames, at most), so it isn't flagged: a vault
/// directory passed with `--vault-dir` is often `0755`. Always `false` off Unix, where
/// there are no mode bits to check.
///
/// ```ignore
/// if is_loosely_permitted(&metadata) { tracing::warn!(...) }
/// ```
pub(crate) fn is_loosely_permitted(metadata: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let loose = if metadata.is_dir() { 0o022 } else { 0o066 };
        metadata.permissions().mode() & loose != 0
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

/// Fsyncs the directory `dir` after a vault file was linked or renamed into it. The
/// change has already happened, so a failure is logged as a warning, not returned: an
/// error would make the session undo a change that is on disk.
///
/// ```ignore
/// temp.persist(path)?;
/// sync_dir_after_commit(&home);
/// ```
pub(crate) fn sync_dir_after_commit(dir: &Path) {
    if sync_dir(dir).is_err() {
        tracing::warn!(event = "vault_directory_sync_failed");
    }
}
