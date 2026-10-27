//! Behaviour of the file audit sink (ADR-0010), tested through the `AuditSink` trait on
//! a temporary vault directory. Vault homes are made by hand, as `init` would.

use std::fs;
use std::path::PathBuf;

use chrono::DateTime;
use tempfile::TempDir;
use vault_core::audit::{AuditSink, Event, FileSink, Line, Record};
use vault_core::storage::Vaultname;

/// A vault directory holding the vault home `alice/`, and a file sink on it.
struct Fixture {
    dir: TempDir,
    sink: FileSink,
}

impl Fixture {
    /// A vault directory with an empty vault home for `alice`.
    ///
    /// ```text
    /// let fx = Fixture::new();
    /// ```
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        fs::create_dir(dir.path().join("alice")).unwrap();
        let sink = FileSink::new(dir.path());
        Self { dir, sink }
    }

    /// Path of `alice`'s audit log.
    ///
    /// ```text
    /// fs::read_to_string(fx.log())
    /// ```
    fn log(&self) -> PathBuf {
        self.dir.path().join("alice").join("audit.log")
    }
}

/// The vaultname `name`.
///
/// ```text
/// fx.sink.append(&vaultname("alice"), &record)
/// ```
fn vaultname(name: &str) -> Vaultname {
    Vaultname::parse(name).unwrap()
}

/// `event` at Unix second `seconds`.
///
/// ```text
/// let record = at(1_767_225_600, Event::Unlocked);
/// ```
fn at(seconds: i64, event: Event) -> Record {
    Record {
        time: DateTime::from_timestamp(seconds, 0).unwrap(),
        event,
    }
}

/// The records among `lines`, assuming all of them parsed.
///
/// ```text
/// assert_eq!(records(&lines), [record]);
/// ```
fn records(lines: &[Line]) -> Vec<Record> {
    lines
        .iter()
        .map(|line| match line {
            Line::Record(record) => record.clone(),
            Line::Unreadable => panic!("unexpected unreadable line"),
        })
        .collect()
}

#[test]
fn appended_record_is_one_json_line_with_utc_time_kind_and_title() {
    let fx = Fixture::new();
    let revealed = at(
        1_767_225_600,
        Event::SecretRevealed {
            title: "GitHub".into(),
        },
    );
    fx.sink.append(&vaultname("alice"), &revealed).unwrap();

    assert_eq!(
        fs::read_to_string(fx.log()).unwrap(),
        "{\"time\":\"2026-01-01T00:00:00Z\",\"kind\":\"secret_revealed\",\"title\":\"GitHub\"}\n"
    );
    let lines = fx.sink.read_recent(&vaultname("alice"), 20).unwrap();
    assert_eq!(records(&lines), [revealed]);
}

#[test]
fn unknown_vaultname_writes_nothing_and_creates_no_file() {
    let fx = Fixture::new();
    let result = fx
        .sink
        .append(&vaultname("bob"), &at(0, Event::UnlockFailed));

    assert!(result.is_err());
    assert!(!fx.dir.path().join("bob").exists());
}

#[cfg(unix)]
#[test]
fn log_is_created_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let fx = Fixture::new();
    fx.sink
        .append(&vaultname("alice"), &at(0, Event::Locked))
        .unwrap();

    let mode = fs::metadata(fx.log()).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[cfg(unix)]
#[test]
fn symlinked_log_is_refused_and_its_target_untouched() {
    let fx = Fixture::new();
    let target = fx.dir.path().join("elsewhere");
    fs::write(&target, "untouched").unwrap();
    std::os::unix::fs::symlink(&target, fx.log()).unwrap();

    assert!(
        fx.sink
            .append(&vaultname("alice"), &at(0, Event::Locked))
            .is_err()
    );
    assert!(fx.sink.read_recent(&vaultname("alice"), 20).is_err());
    assert_eq!(fs::read_to_string(&target).unwrap(), "untouched");
}

#[cfg(unix)]
#[test]
fn symlinked_vault_home_is_refused() {
    let fx = Fixture::new();
    std::os::unix::fs::symlink(fx.dir.path().join("alice"), fx.dir.path().join("mallory")).unwrap();

    assert!(
        fx.sink
            .append(&vaultname("mallory"), &at(0, Event::Locked))
            .is_err()
    );
    assert!(!fx.log().exists());
}

#[test]
fn read_recent_gives_newest_first_up_to_the_limit() {
    let fx = Fixture::new();
    let alice = vaultname("alice");
    let events = [Event::VaultCreated, Event::Locked, Event::Unlocked];
    for (i, event) in events.into_iter().enumerate() {
        fx.sink.append(&alice, &at(i as i64, event)).unwrap();
    }

    let lines = fx.sink.read_recent(&alice, 2).unwrap();
    assert_eq!(
        records(&lines),
        [at(2, Event::Unlocked), at(1, Event::Locked)]
    );
}

#[test]
fn lines_that_do_not_parse_read_as_unreadable() {
    let fx = Fixture::new();
    let alice = vaultname("alice");
    fx.sink.append(&alice, &at(0, Event::Locked)).unwrap();
    let mut log = fs::read(fx.log()).unwrap();
    log.extend_from_slice(
        b"not json\n{\"time\":\"2026-01-01T00:00:00Z\",\"kind\":\"from_the_future\"}\n\xff\xfe\n",
    );
    fs::write(fx.log(), log).unwrap();

    let lines = fx.sink.read_recent(&alice, 20).unwrap();
    assert_eq!(
        lines,
        [
            Line::Unreadable,
            Line::Unreadable,
            Line::Unreadable,
            Line::Record(at(0, Event::Locked)),
        ]
    );
}

#[test]
fn reading_a_vault_home_without_a_log_gives_nothing() {
    let fx = Fixture::new();
    assert_eq!(fx.sink.read_recent(&vaultname("alice"), 20).unwrap(), []);
}

/// Size at which `audit.log` is rotated (ADR-0010).
const ROTATE_AT: usize = 1024 * 1024;

/// Fills `alice`'s log with copies of `record`'s line, as many as fit in 1 MiB.
///
/// ```text
/// let lines = fill_log(&fx, &at(0, Event::Locked));
/// ```
fn fill_log(fx: &Fixture, record: &Record) -> usize {
    let mut line = serde_json::to_string(record).unwrap();
    line.push('\n');
    let count = ROTATE_AT / line.len();
    fs::write(fx.log(), line.repeat(count)).unwrap();
    count
}

#[test]
fn append_past_one_mib_moves_the_log_to_audit_log_1_and_starts_a_new_one() {
    let fx = Fixture::new();
    let alice = vaultname("alice");
    fs::write(fx.dir.path().join("alice/audit.log.1"), "older rotation\n").unwrap();
    let old_lines = fill_log(&fx, &at(0, Event::Locked));
    let full = fs::read(fx.log()).unwrap();

    fx.sink.append(&alice, &at(1, Event::Unlocked)).unwrap();

    assert_eq!(
        fs::read(fx.dir.path().join("alice/audit.log.1")).unwrap(),
        full
    );
    let lines = fx.sink.read_recent(&alice, 20).unwrap();
    assert_eq!(lines[0], Line::Record(at(1, Event::Unlocked)));
    assert_eq!(fs::read_to_string(fx.log()).unwrap().lines().count(), 1);
    assert!(old_lines > 1);
}

#[test]
fn read_recent_continues_into_audit_log_1_after_the_current_log() {
    let fx = Fixture::new();
    let alice = vaultname("alice");
    let old_lines = fill_log(&fx, &at(0, Event::Locked));
    fx.sink.append(&alice, &at(1, Event::Unlocked)).unwrap();

    let lines = fx.sink.read_recent(&alice, 3).unwrap();
    assert_eq!(
        records(&lines),
        [
            at(1, Event::Unlocked),
            at(0, Event::Locked),
            at(0, Event::Locked)
        ]
    );
    assert_eq!(
        fx.sink.read_recent(&alice, usize::MAX).unwrap().len(),
        old_lines + 1
    );
}

#[test]
fn append_that_still_fits_does_not_rotate() {
    let fx = Fixture::new();
    let alice = vaultname("alice");
    fs::write(fx.log(), "x".repeat(ROTATE_AT - 100) + "\n").unwrap();

    fx.sink.append(&alice, &at(1, Event::Unlocked)).unwrap();

    assert!(!fx.dir.path().join("alice/audit.log.1").exists());
}
