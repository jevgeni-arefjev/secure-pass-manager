//! Audit module: the audit log of each vault (ADR-0010).
//!
//! An audit event is one [`Event`], stamped with a UTC time into a [`Record`] and handed
//! to an [`AuditSink`]. [`FileSink`] appends records as JSON Lines to `audit.log` in the
//! vault home (ADR-0009); [`MemorySink`] keeps them in memory for tests.
//!
//! Security:
//! - An [`Event`] names at most the title of a secret, never a field value: its only
//!   text is a `String` title, so a [`HiddenValue`](crate::session::HiddenValue) can't
//!   be put into one.
//! - The log is plaintext and has no tamper evidence: it is a record for the owner,
//!   not forensic evidence. Failing to write it never blocks what it records.
//! - [`FileSink`] never creates a vault home, so a failed unlock of an unknown
//!   vaultname leaves no trace. `audit.log` is opened with `O_APPEND` and `O_NOFOLLOW`
//!   and created `0600` (Unix); looser permissions are logged as a warning.
//!
//! ```
//! use chrono::DateTime;
//! use vault_core::audit::{AuditSink, Event, Line, MemorySink, Record};
//! use vault_core::storage::Vaultname;
//!
//! let sink = MemorySink::default();
//! let alice = Vaultname::parse("alice")?;
//! let time = DateTime::from_timestamp(1_767_225_600, 0).unwrap();
//! sink.append(&alice, &Record { time, event: Event::Unlocked })?;
//! assert_eq!(sink.read_recent(&alice, 20)?, [Line::Record(Record { time, event: Event::Unlocked })]);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::storage::{self, Vaultname};

/// Name of the audit log inside a vault home (ADR-0009).
const LOG_FILE: &str = "audit.log";

/// Where the log goes once it is full, replacing any older one.
const ROTATED_LOG_FILE: &str = "audit.log.1";

/// Largest the log may grow; an append that would pass this rotates it first.
const MAX_LOG_BYTES: u64 = 1024 * 1024;

/// One security-relevant thing that happened to a vault. Stored as its snake_case
/// `kind` plus, for secret events, the secret's `title`.
///
/// ```
/// use vault_core::audit::Event;
/// let event = Event::SecretRevealed { title: "GitHub".into() };
/// assert_eq!(event.title(), Some("GitHub"));
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    /// `init` created the vault.
    VaultCreated,
    /// The vault was unlocked.
    Unlocked,
    /// A wrong master password was given for this (existing) vault.
    UnlockFailed,
    /// The owner locked the vault.
    Locked,
    /// The vault locked itself after the idle timeout.
    AutoLocked,
    /// Another session saved first, so this one locked.
    LockedOnConflict,
    /// A termination signal locked the vault.
    TerminatedBySignal,
    /// A secret with a new title was saved.
    SecretAdded {
        /// Title of the secret.
        title: String,
    },
    /// A secret replaced the one with the same title.
    SecretReplaced {
        /// Title of the secret.
        title: String,
    },
    /// A secret was removed.
    SecretRemoved {
        /// Title of the secret.
        title: String,
    },
    /// A secret's hidden fields were shown or copied.
    SecretRevealed {
        /// Title of the secret.
        title: String,
    },
    /// The master password was changed.
    MasterPasswordChanged,
    /// A master password change was refused: the current master password was wrong.
    MasterPasswordChangeFailed,
}

impl Event {
    /// The title of the secret this event concerns, if any.
    ///
    /// ```
    /// # use vault_core::audit::Event;
    /// assert_eq!(Event::Locked.title(), None);
    /// ```
    #[must_use]
    pub fn title(&self) -> Option<&str> {
        match self {
            Self::SecretAdded { title }
            | Self::SecretReplaced { title }
            | Self::SecretRemoved { title }
            | Self::SecretRevealed { title } => Some(title),
            Self::VaultCreated
            | Self::Unlocked
            | Self::UnlockFailed
            | Self::Locked
            | Self::AutoLocked
            | Self::LockedOnConflict
            | Self::TerminatedBySignal
            | Self::MasterPasswordChanged
            | Self::MasterPasswordChangeFailed => None,
        }
    }
}

/// An [`Event`] and when it happened: one line of the audit log.
///
/// ```
/// use chrono::DateTime;
/// use vault_core::audit::{Event, Record};
///
/// let record = Record { time: DateTime::from_timestamp(0, 0).unwrap(), event: Event::Locked };
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// When it happened, stored as an RFC 3339 UTC timestamp.
    pub time: DateTime<Utc>,
    /// What happened.
    #[serde(flatten)]
    pub event: Event,
}

/// One line read back from an audit log.
///
/// ```
/// use vault_core::audit::Line;
///
/// fn show(line: &Line) -> String {
///     match line {
///         Line::Record(record) => format!("{:?}", record.event),
///         Line::Unreadable => "<unreadable event>".into(),
///     }
/// }
/// assert_eq!(show(&Line::Unreadable), "<unreadable event>");
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Line {
    /// A record that parsed.
    Record(Record),
    /// A line that isn't a record this build knows (corrupt, or from a newer build).
    Unreadable,
}

/// Why the audit log couldn't be written or read. The message is fixed: it never
/// carries a path or file contents.
///
/// ```
/// use vault_core::audit::AuditError;
/// assert_eq!(AuditError.to_string(), "audit log can't be accessed");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditError;

impl fmt::Display for AuditError {
    /// Writes the fixed message.
    ///
    /// ```
    /// # use vault_core::audit::AuditError;
    /// let message = AuditError.to_string();
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("audit log can't be accessed")
    }
}

impl std::error::Error for AuditError {}

/// Where audit records go, per vault. The session only ever passes the vaultname it
/// unlocked, so one owner never reads another's log (ADR-0001).
///
/// ```
/// use vault_core::audit::{AuditSink, Event, Line};
/// use vault_core::storage::Vaultname;
///
/// /// Works with any sink.
/// fn unlocks(sink: &dyn AuditSink, name: &Vaultname) -> usize {
///     let lines = sink.read_recent(name, 100).unwrap_or_default();
///     lines.iter().filter(|l| matches!(l, Line::Record(r) if r.event == Event::Unlocked)).count()
/// }
/// ```
pub trait AuditSink: Send + Sync {
    /// Appends `record` to `name`'s audit log.
    ///
    /// ```
    /// # use chrono::DateTime;
    /// # use vault_core::audit::{AuditSink, Event, MemorySink, Record};
    /// # use vault_core::storage::Vaultname;
    /// let sink = MemorySink::default();
    /// let record = Record { time: DateTime::from_timestamp(0, 0).unwrap(), event: Event::Locked };
    /// sink.append(&Vaultname::parse("alice")?, &record)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn append(&self, name: &Vaultname, record: &Record) -> Result<(), AuditError>;

    /// Up to `limit` of `name`'s most recent lines, newest first. An empty log gives
    /// an empty list.
    ///
    /// ```
    /// # use vault_core::audit::{AuditSink, MemorySink};
    /// # use vault_core::storage::Vaultname;
    /// let sink = MemorySink::default();
    /// assert!(sink.read_recent(&Vaultname::parse("alice")?, 20)?.is_empty());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn read_recent(&self, name: &Vaultname, limit: usize) -> Result<Vec<Line>, AuditError>;
}

/// Audit logs as `audit.log` files in the vault homes of one vault directory.
///
/// ```
/// use vault_core::audit::FileSink;
/// let sink = FileSink::new("/home/alice/.local/share/secure-pass-manager/vaults");
/// ```
#[derive(Clone, Debug)]
pub struct FileSink {
    dir: PathBuf,
}

impl FileSink {
    /// A sink for the vault directory `dir`, the same one the vault store uses.
    ///
    /// ```
    /// # use vault_core::audit::FileSink;
    /// let dir = tempfile::tempdir()?;
    /// let sink = FileSink::new(dir.path());
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }
}

impl AuditSink for FileSink {
    /// Appends `record` as one JSON line, in one write.
    ///
    /// ```
    /// # use chrono::DateTime;
    /// # use vault_core::audit::{AuditSink, Event, FileSink, Record};
    /// # use vault_core::storage::Vaultname;
    /// # let dir = tempfile::tempdir()?;
    /// # std::fs::create_dir(dir.path().join("alice"))?;
    /// let sink = FileSink::new(dir.path());
    /// let record = Record { time: DateTime::from_timestamp(0, 0).unwrap(), event: Event::Locked };
    /// sink.append(&Vaultname::parse("alice")?, &record)?;
    /// assert!(dir.path().join("alice/audit.log").is_file());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn append(&self, name: &Vaultname, record: &Record) -> Result<(), AuditError> {
        let home = storage::existing_vault_home(&self.dir, name).map_err(|_| AuditError)?;
        let mut line = serde_json::to_vec(record).map_err(|_| AuditError)?;
        line.push(b'\n');
        let mut options = OpenOptions::new();
        options.append(true).create(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let path = home.join(LOG_FILE);
        let mut file = open_log(&options, &path, name)?;
        let size = file.metadata().map_err(io_error)?.len();
        if size.saturating_add(line.len() as u64) > MAX_LOG_BYTES {
            drop(file);
            fs::rename(&path, home.join(ROTATED_LOG_FILE)).map_err(io_error)?;
            file = open_log(&options, &path, name)?;
        }
        file.write_all(&line).map_err(io_error)
    }

    /// Reads the current log, then `audit.log.1`, each newest line first.
    ///
    /// ```
    /// # use vault_core::audit::{AuditSink, FileSink};
    /// # use vault_core::storage::Vaultname;
    /// # let dir = tempfile::tempdir()?;
    /// # std::fs::create_dir(dir.path().join("alice"))?;
    /// let sink = FileSink::new(dir.path());
    /// assert!(sink.read_recent(&Vaultname::parse("alice")?, 20)?.is_empty());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn read_recent(&self, name: &Vaultname, limit: usize) -> Result<Vec<Line>, AuditError> {
        let home = storage::existing_vault_home(&self.dir, name).map_err(|_| AuditError)?;
        let mut lines = Vec::new();
        for file_name in [LOG_FILE, ROTATED_LOG_FILE] {
            if lines.len() >= limit {
                break;
            }
            let mut bytes = Vec::new();
            match open_log(OpenOptions::new().read(true), &home.join(file_name), name) {
                Ok(mut file) => drop(file.read_to_end(&mut bytes).map_err(io_error)?),
                Err(LogOpenError::NotFound) => continue,
                Err(LogOpenError::Refused) => return Err(AuditError),
            }
            let newest_first = bytes
                .split(|&b| b == b'\n')
                .filter(|line| !line.is_empty())
                .rev()
                .map(parse_line);
            lines.extend(newest_first.take(limit - lines.len()));
        }
        Ok(lines)
    }
}

/// Why [`open_log`] gave no file.
enum LogOpenError {
    /// There is no log file (yet).
    NotFound,
    /// It is a symlink or not a regular file, or the file system failed.
    Refused,
}

impl From<LogOpenError> for AuditError {
    /// Any failure to open the log is an [`AuditError`].
    ///
    /// ```ignore
    /// let file = open_log(&options, &path, name)?;
    /// ```
    fn from(_: LogOpenError) -> Self {
        AuditError
    }
}

/// Opens the log file at `path` with `options`, never following a symlink
/// (`O_NOFOLLOW`), and checks the opened file is a regular file.
///
/// Security: the check is on the opened file itself, so the file can't be swapped
/// between check and use. Group- or world-writable permissions are logged as a
/// warning, not refused.
///
/// ```ignore
/// let file = open_log(OpenOptions::new().read(true), &home.join(LOG_FILE), name)?;
/// ```
fn open_log(options: &OpenOptions, path: &Path, name: &Vaultname) -> Result<File, LogOpenError> {
    let mut options = options.clone();
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NOFOLLOW);
    let file = match options.open(path) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Err(LogOpenError::NotFound),
        result => result.map_err(|_| LogOpenError::Refused)?,
    };
    let metadata = file.metadata().map_err(|_| LogOpenError::Refused)?;
    if !metadata.is_file() {
        return Err(LogOpenError::Refused);
    }
    if storage::is_loosely_permitted(&metadata) {
        tracing::warn!(event = "audit_log_permissions_loose", vaultname = %name);
    }
    Ok(file)
}

/// One stored line as a [`Line`]; anything that isn't a known record is
/// [`Line::Unreadable`].
///
/// ```ignore
/// assert_eq!(parse_line(b"garbage"), Line::Unreadable);
/// ```
fn parse_line(line: &[u8]) -> Line {
    serde_json::from_slice(line).map_or(Line::Unreadable, Line::Record)
}

/// Maps a file system error to [`AuditError`], dropping its message (which may contain
/// a path).
///
/// ```ignore
/// file.write_all(&line).map_err(io_error)?;
/// ```
fn io_error(_: io::Error) -> AuditError {
    AuditError
}

/// Audit logs kept in memory, for tests.
///
/// ```
/// use vault_core::audit::MemorySink;
/// let sink = MemorySink::default();
/// ```
#[derive(Debug, Default)]
pub struct MemorySink {
    records: Mutex<Vec<(Vaultname, Record)>>,
}

impl AuditSink for MemorySink {
    /// Keeps `record` in memory under `name`.
    ///
    /// ```
    /// # use chrono::DateTime;
    /// # use vault_core::audit::{AuditSink, Event, MemorySink, Record};
    /// # use vault_core::storage::Vaultname;
    /// let sink = MemorySink::default();
    /// let record = Record { time: DateTime::from_timestamp(0, 0).unwrap(), event: Event::Locked };
    /// sink.append(&Vaultname::parse("alice")?, &record)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn append(&self, name: &Vaultname, record: &Record) -> Result<(), AuditError> {
        self.records
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((name.clone(), record.clone()));
        Ok(())
    }

    /// `name`'s records, newest first; other vaults' records are never returned.
    ///
    /// ```
    /// # use chrono::DateTime;
    /// # use vault_core::audit::{AuditSink, Event, MemorySink, Record};
    /// # use vault_core::storage::Vaultname;
    /// let sink = MemorySink::default();
    /// let record = Record { time: DateTime::from_timestamp(0, 0).unwrap(), event: Event::Locked };
    /// sink.append(&Vaultname::parse("bob")?, &record)?;
    /// assert!(sink.read_recent(&Vaultname::parse("alice")?, 20)?.is_empty());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn read_recent(&self, name: &Vaultname, limit: usize) -> Result<Vec<Line>, AuditError> {
        let records = self.records.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(records
            .iter()
            .rev()
            .filter(|(owner, _)| owner == name)
            .take(limit)
            .map(|(_, record)| Line::Record(record.clone()))
            .collect())
    }
}
