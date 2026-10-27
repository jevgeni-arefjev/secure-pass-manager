//! Turns secrets and audit events into terminal text: the `get` view, the `list` table
//! and the `log` view.
//!
//! Security:
//! - Every stored text is escaped before it reaches the terminal ([`escape`]): control
//!   characters and invisible or bidirectional formatting characters are shown as
//!   `\x1b` / `\u{202e}` escapes, so a crafted vault can't drive the terminal or
//!   disguise what is printed. The core already refuses them on save; this also covers
//!   vaults written by other builds.
//! - A masked hidden field is shown as a single `*`, whatever its length (ADR-0008).
//! - Output is returned in zeroizing strings, like the fields it is built from.

use std::fmt::{Display, Write};

use chrono::{TimeZone, Utc};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};
use vault_core::audit::{Event, Line};
use vault_core::session::{FieldValue, HiddenValue, Secret};
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
    /// Hidden fields show their value (`get --show`).
    Shown,
}

/// `text` with every control, invisible or bidirectional formatting character replaced
/// by a visible escape. With `multiline`, newlines and tabs are kept (for notes).
///
/// ```
/// use vault_cli::render::escape;
/// assert_eq!(escape("evil\u{1b}[2J", false).as_str(), r"evil\x1b[2J");
/// assert_eq!(escape("txt\u{202e}gpj.exe", false).as_str(), r"txt\u{202e}gpj.exe");
/// assert_eq!(escape("line 1\nline 2", true).as_str(), "line 1\nline 2");
/// ```
#[must_use]
pub fn escape(text: &str, multiline: bool) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(text.len()));
    for c in text.chars() {
        let kept_whitespace = multiline && matches!(c, '\n' | '\t');
        if kept_whitespace || !(c.is_control() || is_invisible(c)) {
            out.push(c);
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
        Reveal::Shown => escape(value.reveal(), false),
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
        if let Some(title) = record.event.title() {
            let _ = write!(out, " '{}'", escape(title, false).as_str());
        }
    }
    out
}

/// What an audit event means, in words, without its title.
///
/// ```ignore
/// assert_eq!(describe(&Event::AutoLocked), "locked (idle)");
/// ```
fn describe(event: &Event) -> &'static str {
    match event {
        Event::VaultCreated => "vault created",
        Event::Unlocked => "unlocked",
        Event::UnlockFailed => "unlock failed (wrong master password)",
        Event::Locked => "locked",
        Event::AutoLocked => "locked (idle)",
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
    }
}

/// Whether `c` is an invisible or bidirectional formatting character (zero-width
/// spaces, direction overrides and isolates, byte order mark).
///
/// ```ignore
/// assert!(is_invisible('\u{202e}'));
/// ```
fn is_invisible(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}')
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
