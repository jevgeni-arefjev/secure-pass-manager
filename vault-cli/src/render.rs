//! Turns secrets and audit events into terminal text: the `get` view, the `list` table,
//! the `log` view, the problems of a refused save and the cause kind of an internal
//! failure.
//!
//! Security:
//! - Every stored text is escaped before it reaches the terminal ([`escape`]): exactly
//!   the characters the core refuses in non-hidden fields ([`is_unsafe_char`]: control
//!   characters, the Unicode format category, line and paragraph separators) are shown
//!   as `\x1b` / `\u{202e}` escapes, so a crafted vault can't drive the terminal or
//!   disguise what is printed. The core refuses them on save; this also covers vaults
//!   written by other builds and secrets saved under older rules.
//! - A masked hidden field is shown as a single `*`, whatever its length (ADR-0008).
//!   A shown one (`get --show`) is escaped the same way, and since it is stored exactly
//!   (ADR-0013) and may hold a `\` of its own, `\` is shown as `\\` too
//!   ([`escape_hidden`]): an escape in the output always stands for one character.
//!   `--copy` is the exact path.
//! - Output is returned in zeroizing strings, like the fields it is built from.

use std::fmt::{Display, Write};
use std::io::ErrorKind;

use chrono::{TimeZone, Utc};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};
use vault_core::audit::{Event, Line};
use vault_core::session::{
    CustomFieldPart, FieldProblem, FieldValue, HiddenValue, InvalidSecret, Secret, SecretField,
    is_unsafe_char,
};
use vault_core::storage::LOCK_HELD_TOO_LONG;
use zeroize::Zeroizing;

/// What a masked hidden field looks like.
const MASK: &str = "*";

/// Widest a `list` column gets before its text is cut short with `…`.
const MAX_COLUMN_WIDTH: usize = 32;

/// Whether hidden fields are shown in the `get` view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reveal {
    /// Every hidden field shows as `*` (the default).
    Masked,
    /// Hidden fields show their value (`get --show`), with invisible characters and
    /// `\` as escapes.
    Shown,
}

/// `text` with every character the core refuses in non-hidden fields
/// ([`is_unsafe_char`]) replaced by a visible escape. With `multiline`, newlines and
/// tabs are kept (for notes).
///
/// ```
/// use vault_cli::render::escape;
/// assert_eq!(escape("evil\u{1b}[2J", false).as_str(), r"evil\x1b[2J");
/// assert_eq!(escape("txt\u{202e}gpj.exe", false).as_str(), r"txt\u{202e}gpj.exe");
/// assert_eq!(escape("soft\u{ad}hyphen", false).as_str(), r"soft\xadhyphen");
/// assert_eq!(escape("line 1\nline 2", true).as_str(), "line 1\nline 2");
/// ```
#[must_use]
pub fn escape(text: &str, multiline: bool) -> Zeroizing<String> {
    escape_where(text, |c| is_unsafe_char(c, multiline))
}

/// A shown hidden value: like [`escape`] on one line, and with every `\` shown as
/// `\\`, so a value holding the text `\xad` can't be mistaken for one holding U+00AD.
///
/// Security: the result holds the hidden value; let it drop straight after printing.
///
/// ```ignore
/// assert_eq!(escape_hidden("a\\xad\u{ad}").as_str(), r"a\\xad\xad");
/// ```
fn escape_hidden(value: &str) -> Zeroizing<String> {
    escape_where(value, |c| c == '\\' || is_unsafe_char(c, false))
}

/// `text` with every character for which `escaped` holds replaced by a visible escape:
/// `\\` for a backslash, `\x..` up to U+00FF, else `\u{..}`.
///
/// ```ignore
/// let out = escape_where(text, |c| is_unsafe_char(c, false));
/// ```
fn escape_where(text: &str, escaped: impl Fn(char) -> bool) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(text.len()));
    for c in text.chars() {
        if !escaped(c) {
            out.push(c);
        } else if c == '\\' {
            out.push_str("\\\\");
        } else if u32::from(c) <= 0xff {
            let _ = write!(out, "\\x{:02x}", u32::from(c));
        } else {
            let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
        }
    }
    out
}

/// The `get` view of one secret: one `label: value` line per field that is set, in a
/// fixed order, with created/updated times shown in `tz`.
///
/// Security: with [`Reveal::Shown`] the result holds hidden values; print it only to a
/// terminal and let it drop straight after.
///
/// ```
/// use chrono::Utc;
/// use vault_cli::render::{self, Reveal};
/// use vault_core::session::{HiddenValue, Secret};
///
/// let github = Secret::new("GitHub")
///     .with_username("alice")
///     .with_password(HiddenValue::new("s3cret!".into()));
/// let view = render::secret(&github, Reveal::Masked, &Utc);
/// assert_eq!(view.as_str(), "title:    GitHub\nusername: alice\npassword: *");
/// ```
#[must_use]
pub fn secret<Tz>(secret: &Secret, reveal: Reveal, tz: &Tz) -> Zeroizing<String>
where
    Tz: TimeZone,
    Tz::Offset: Display,
{
    let hidden = |value: &HiddenValue| match reveal {
        Reveal::Masked => Zeroizing::new(MASK.to_owned()),
        Reveal::Shown => escape_hidden(value.reveal()),
    };
    let mut rows: Vec<(Zeroizing<String>, Zeroizing<String>)> = Vec::new();
    let mut row = |label: &str, value: Zeroizing<String>| {
        rows.push((escape(label, false), value));
    };
    row("title", escape(secret.title(), false));
    if let Some(username) = secret.username() {
        row("username", escape(username, false));
    }
    if let Some(password) = secret.password() {
        row("password", hidden(password));
    }
    if let Some(url) = secret.url() {
        row("url", escape(url, false));
    }
    let tags = join_tags(secret);
    if !tags.is_empty() {
        row("tags", tags);
    }
    if let Some(notes) = secret.notes() {
        row("notes", escape(notes, true));
    }
    for field in secret.custom_fields() {
        let value = match field.value() {
            FieldValue::Plain(text) => escape(text, false),
            FieldValue::Hidden(value) => hidden(value),
        };
        row(field.name(), value);
    }
    for (label, at) in [
        ("created", secret.created_at()),
        ("updated", secret.updated_at()),
    ] {
        if at > 0 {
            row(label, Zeroizing::new(local_time(at, tz)));
        }
    }
    layout_rows(&rows)
}

/// The `list` table: a header and one row per secret with its title, username, URL and
/// tags. Notes and custom fields are left out, and so is every hidden field.
///
/// ```
/// use vault_cli::render;
/// use vault_core::session::Secret;
///
/// let github = Secret::new("GitHub").with_username("alice");
/// let table = render::secret_list(&[&github]);
/// assert_eq!(table.as_str(), "TITLE   USERNAME  URL  TAGS\nGitHub  alice");
/// ```
#[must_use]
pub fn secret_list(secrets: &[&Secret]) -> Zeroizing<String> {
    if secrets.is_empty() {
        return Zeroizing::new("no secrets yet".to_owned());
    }
    let header = ["TITLE", "USERNAME", "URL", "TAGS"].map(|h| Zeroizing::new(h.to_owned()));
    let mut table = vec![header];
    for secret in secrets {
        let cell = |text: Option<&str>| truncate(&escape(text.unwrap_or(""), false));
        table.push([
            cell(Some(secret.title())),
            cell(secret.username()),
            cell(secret.url()),
            truncate(&join_tags(secret)),
        ]);
    }
    let widths: Vec<usize> = (0..4)
        .map(|col| table.iter().map(|row| row[col].width()).max().unwrap_or(0))
        .collect();
    let mut out = Zeroizing::new(String::new());
    for (i, row) in table.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let mut line = Zeroizing::new(String::new());
        for (col, cell) in row.iter().enumerate() {
            if col > 0 {
                line.push_str("  ");
            }
            line.push_str(cell);
            if col < 3 {
                pad(&mut line, widths[col] - cell.width());
            }
        }
        out.push_str(line.trim_end());
    }
    out
}

/// The `log` view: one `YYYY-MM-DD HH:MM:SS  <what happened>` line per audit log line,
/// in the given order, with times in `tz`. A line that didn't parse shows as
/// `<unreadable event>`.
///
/// Security: titles come from a plaintext file anyone with access to the vault home
/// could have edited, so they are escaped like all stored text.
///
/// ```
/// use chrono::{DateTime, Utc};
/// use vault_cli::render;
/// use vault_core::audit::{Event, Line, Record};
///
/// let time = DateTime::from_timestamp(1_767_225_600, 0).unwrap();
/// let lines = [Line::Record(Record { time, event: Event::Unlocked }), Line::Unreadable];
/// assert_eq!(
///     render::audit_log(&lines, &Utc).as_str(),
///     "2026-01-01 00:00:00  unlocked\n<unreadable event>"
/// );
/// ```
#[must_use]
pub fn audit_log<Tz>(lines: &[Line], tz: &Tz) -> Zeroizing<String>
where
    Tz: TimeZone,
    Tz::Offset: Display,
{
    if lines.is_empty() {
        return Zeroizing::new("no audit events yet".to_owned());
    }
    let mut out = Zeroizing::new(String::new());
    for (i, line) in lines.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let Line::Record(record) = line else {
            out.push_str("<unreadable event>");
            continue;
        };
        let time = record.time.with_timezone(tz).format("%Y-%m-%d %H:%M:%S");
        let _ = write!(out, "{time}  {}", describe(&record.event));
        if let Event::BackupCreated { revision } = record.event {
            let _ = write!(out, " (revision {revision})");
        }
        if let Some(title) = record.event.title() {
            let _ = write!(out, " '{}'", escape(title, false).as_str());
        }
    }
    out
}

/// What an audit event means, in words, without its title.
///
/// ```ignore
/// assert_eq!(describe(&Event::AutoLocked), "auto-locked");
/// ```
fn describe(event: &Event) -> &'static str {
    match event {
        Event::VaultCreated => "vault created",
        Event::Unlocked => "unlocked",
        Event::UnlockFailed => "unlock failed (wrong master password)",
        Event::Locked => "locked",
        Event::AutoLocked => "auto-locked",
        Event::LockedOnConflict => "locked (changed by another session)",
        Event::TerminatedBySignal => "locked (terminated by signal)",
        Event::SecretAdded { .. } => "secret added",
        Event::SecretReplaced { .. } => "secret replaced",
        Event::SecretRemoved { .. } => "secret removed",
        Event::SecretRevealed { .. } => "secret revealed",
        Event::MasterPasswordChanged => "master password changed",
        Event::MasterPasswordChangeFailed => {
            "master password change failed (wrong current password)"
        }
        Event::BackupCreated { .. } => "backup created",
    }
}

/// The secret's tags, escaped and joined with `, `.
///
/// ```ignore
/// assert_eq!(join_tags(&secret).as_str(), "work, dev");
/// ```
fn join_tags(secret: &Secret) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::new());
    for (i, tag) in secret.tags().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&escape(tag, false));
    }
    out
}

/// Unix seconds as a local `YYYY-MM-DD HH:MM` in `tz`.
///
/// ```ignore
/// assert_eq!(local_time(0, &Utc), "1970-01-01 00:00");
/// ```
fn local_time<Tz>(unix_seconds: u64, tz: &Tz) -> String
where
    Tz: TimeZone,
    Tz::Offset: Display,
{
    let seconds = i64::try_from(unix_seconds).unwrap_or(i64::MAX);
    let utc = Utc.timestamp_opt(seconds, 0).single().unwrap_or_default();
    utc.with_timezone(tz).format("%Y-%m-%d %H:%M").to_string()
}

/// Lays out `label: value` rows with the values in one column; extra lines of a
/// multi-line value are indented to that column.
///
/// ```ignore
/// layout_rows(&rows) // "title:    GitHub\nusername: alice"
/// ```
fn layout_rows(rows: &[(Zeroizing<String>, Zeroizing<String>)]) -> Zeroizing<String> {
    let label_width = rows
        .iter()
        .map(|(label, _)| label.width())
        .max()
        .unwrap_or(0);
    let mut out = Zeroizing::new(String::new());
    for (i, (label, value)) in rows.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        for (j, line) in value.split('\n').enumerate() {
            if j == 0 {
                out.push_str(label);
                out.push(':');
                pad(&mut out, label_width - label.width() + 1);
            } else {
                out.push('\n');
                pad(&mut out, label_width + 2);
            }
            out.push_str(line);
        }
    }
    out
}

/// `text` cut to [`MAX_COLUMN_WIDTH`] display columns, ending in `…` if it was cut.
///
/// ```ignore
/// assert_eq!(truncate(&long_url).width(), MAX_COLUMN_WIDTH);
/// ```
fn truncate(text: &str) -> Zeroizing<String> {
    if text.width() <= MAX_COLUMN_WIDTH {
        return Zeroizing::new(text.to_owned());
    }
    let mut out = Zeroizing::new(String::new());
    let mut width = 0;
    for c in text.chars() {
        let w = c.width().unwrap_or(0);
        if width + w > MAX_COLUMN_WIDTH - 1 {
            break;
        }
        out.push(c);
        width += w;
    }
    out.push('…');
    out
}

/// Appends `n` spaces.
///
/// ```ignore
/// pad(&mut line, 3);
/// ```
fn pad(out: &mut String, n: usize) {
    out.extend(std::iter::repeat_n(' ', n));
}

/// The cause kind of an internal failure in words, as the CLI shows it after the
/// generic message (ADR-0014): `vault storage failed (disk full)`. Only a fixed set of
/// kinds is worded ([`is_worded`]); any other is "unexpected file system error", and
/// the exact kind follows in the `internal_error` diagnostic
/// ([`crate::diagnostics`]).
///
/// Security: fixed text, never the OS error message (which can carry a path).
///
/// ```
/// use std::io::ErrorKind;
/// use vault_cli::render;
/// assert_eq!(render::cause_kind(ErrorKind::StorageFull), "disk full");
/// assert_eq!(render::cause_kind(ErrorKind::Interrupted), "unexpected file system error");
/// ```
#[must_use]
pub fn cause_kind(kind: ErrorKind) -> &'static str {
    worded(kind).unwrap_or("unexpected file system error")
}

/// Whether [`cause_kind`] has words of its own for `kind`.
///
/// ```
/// use std::io::ErrorKind;
/// assert!(vault_cli::render::is_worded(ErrorKind::StorageFull));
/// assert!(!vault_cli::render::is_worded(ErrorKind::NotADirectory));
/// ```
#[must_use]
pub fn is_worded(kind: ErrorKind) -> bool {
    worded(kind).is_some()
}

/// The words for `kind`, if it is one of the fixed set.
///
/// ```ignore
/// assert_eq!(worded(ErrorKind::StorageFull), Some("disk full"));
/// ```
fn worded(kind: ErrorKind) -> Option<&'static str> {
    Some(match kind {
        ErrorKind::StorageFull => "disk full",
        ErrorKind::PermissionDenied => "permission denied",
        ErrorKind::ReadOnlyFilesystem => "read-only file system",
        LOCK_HELD_TOO_LONG => "vault is busy in another session",
        _ => return None,
    })
}

/// Every problem of a refused save, one per line under a heading, each labelled with
/// the field it is about (tags and custom fields numbered from 1, as entered).
///
/// Security: labels and messages are fixed text; no value is printed.
///
/// ```
/// use vault_cli::render;
/// # fn show(invalid: &vault_core::session::InvalidSecret) {
/// eprintln!("vault: {}", render::invalid_secret(invalid));
/// // vault: secret not saved:
/// //   tag 2: tags must be unique, ignoring case
/// # }
/// ```
#[must_use]
pub fn invalid_secret(invalid: &InvalidSecret) -> String {
    refused(invalid.problems())
}

/// A save refused for one field given with the command (the title of `save`), in the
/// same form as [`invalid_secret`].
///
/// Security: the label and message are fixed text; no value is printed.
///
/// ```
/// use vault_cli::render;
/// use vault_core::session::FieldProblem;
/// assert!(render::refused_field(&FieldProblem::Title).starts_with("secret not saved:\n  title: "));
/// ```
#[must_use]
pub fn refused_field(problem: &FieldProblem) -> String {
    refused(std::slice::from_ref(problem))
}

/// The heading of a refused save and one `<field>: <rule>` line per problem.
///
/// ```ignore
/// refused(invalid.problems())
/// ```
fn refused(problems: &[FieldProblem]) -> String {
    let mut out = String::from("secret not saved:");
    for problem in problems {
        let _ = write!(out, "\n  {}", field_problem(problem));
    }
    out
}

/// One problem as `<field>: <rule>`, naming the field as the person entered it (tags
/// and custom fields numbered from 1); the vault shell prints it before asking again.
///
/// Security: the label and message are fixed text; no value is printed.
///
/// ```
/// use vault_cli::render;
/// use vault_core::session::FieldProblem;
/// assert_eq!(
///     render::field_problem(&FieldProblem::DuplicateTag(2)),
///     "tag 3: tags must be unique, ignoring case"
/// );
/// ```
#[must_use]
pub fn field_problem(problem: &FieldProblem) -> String {
    format!("{}: {problem}", problem_label(problem))
}

/// The field a problem is about, as the person entered it: `title`, `tags`, `tag 2`,
/// `custom field 1 name`, ...
///
/// ```ignore
/// assert_eq!(problem_label(&FieldProblem::CustomFieldValue(0)), "custom field 1 value");
/// ```
fn problem_label(problem: &FieldProblem) -> String {
    let field = match problem.field() {
        SecretField::Title => "title",
        SecretField::Username => "username",
        SecretField::Password => "password",
        SecretField::Url => "URL",
        SecretField::Notes => "notes",
        SecretField::Tags => "tag",
        SecretField::CustomFields => "custom field",
    };
    let Some(index) = problem.index() else {
        return match problem.field() {
            SecretField::Tags => "tags".to_owned(),
            SecretField::CustomFields => "custom fields".to_owned(),
            _ => field.to_owned(),
        };
    };
    let part = match problem.part() {
        Some(CustomFieldPart::Name) => " name",
        Some(CustomFieldPart::Value) => " value",
        None => "",
    };
    format!("{field} {}{part}", index + 1)
}
