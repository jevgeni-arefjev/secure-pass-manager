//! Behaviour of the CLI's terminal output (`get` view, `list` table, `log` lines,
//! escaping), tested only through its public API.

use std::io::ErrorKind;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde_json::Value;
use vault_cli::render::{self, Reveal};
use vault_core::audit::{Event, Line, MemorySink, Record};
use vault_core::crypto::MasterPassword;
use vault_core::session::{CustomField, HiddenValue, Secret, Session, SessionConfig};
use vault_core::storage::{FileStore, LOCK_HELD_TOO_LONG};

/// Builds a hidden value from a literal.
///
/// ```text
/// Secret::new("GitHub").with_password(hidden("s3cret!"))
/// ```
fn hidden(s: &str) -> HiddenValue {
    HiddenValue::new(s.to_owned())
}

/// A secret with every kind of field set.
///
/// ```text
/// render::secret(&full_secret(), Reveal::Masked, &Utc)
/// ```
fn full_secret() -> Secret {
    Secret::new("GitHub")
        .with_username("alice")
        .with_password(hidden("a-very-long-password-indeed"))
        .with_url("https://github.com")
        .with_tag("work")
        .with_tag("dev")
        .with_notes("first line\nsecond line")
        .with_custom_field(CustomField::plain("region", "eu-west"))
        .with_custom_field(CustomField::hidden("recovery code", hidden("1234-5678")))
}

/// The shared fixture of unsafe and safe characters, also read by the core and web tests.
const FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../fixtures/unsafe-characters.json"
));

/// A character from a fixture code point such as `"202E"`.
///
/// ```text
/// assert_eq!(code_point("0041"), 'A');
/// ```
fn code_point(hex: &str) -> char {
    char::from_u32(u32::from_str_radix(hex, 16).unwrap()).unwrap()
}

/// The visible escape `render::escape` shows for `c`: `\x1b` up to U+00FF, else `\u{202e}`.
///
/// ```text
/// assert_eq!(escaped('\u{1b}'), r"\x1b");
/// ```
fn escaped(c: char) -> String {
    let c = u32::from(c);
    if c <= 0xff {
        format!("\\x{c:02x}")
    } else {
        format!("\\u{{{c:x}}}")
    }
}

#[test]
fn escape_shows_every_unsafe_character_of_the_shared_fixture_and_keeps_its_safe_ones() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let multiline_safe: Vec<char> = fixture["multiline_safe"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| code_point(c.as_str().unwrap()))
        .collect();
    let mut checked = 0;
    for range in fixture["unsafe"].as_array().unwrap() {
        let from = u32::from(code_point(range["from"].as_str().unwrap()));
        let to = u32::from(code_point(range["to"].as_str().unwrap()));
        for c in (from..=to).map(|c| char::from_u32(c).unwrap()) {
            let text = format!("a{c}b");
            let single = format!("a{}b", escaped(c));
            assert_eq!(
                render::escape(&text, false).as_str(),
                single,
                "U+{:04X}",
                u32::from(c)
            );
            let multi = if multiline_safe.contains(&c) {
                &text
            } else {
                &single
            };
            assert_eq!(
                render::escape(&text, true).as_str(),
                multi,
                "U+{:04X}",
                u32::from(c)
            );
            checked += 1;
        }
    }
    assert!(checked > 200);
    for entry in fixture["safe"].as_array().unwrap() {
        let text = format!("a{}b", code_point(entry["char"].as_str().unwrap()));
        assert_eq!(render::escape(&text, false).as_str(), text);
    }
}

#[test]
fn escape_shows_terminal_control_sequences_as_text() {
    assert_eq!(render::escape("a\u{1b}[2Jb", false).as_str(), r"a\x1b[2Jb");
    assert_eq!(render::escape("\0\u{7f}", false).as_str(), r"\x00\x7f");
    // 8-bit CSI: some terminals treat it like ESC [
    assert_eq!(render::escape("\u{9b}31m", false).as_str(), r"\x9b31m");
}

#[test]
fn escape_shows_invisible_and_bidi_characters_as_text() {
    assert_eq!(
        render::escape("txt\u{202e}gpj.exe", false).as_str(),
        r"txt\u{202e}gpj.exe"
    );
    assert_eq!(
        render::escape("pay\u{200b}pal", false).as_str(),
        r"pay\u{200b}pal"
    );
    assert_eq!(
        render::escape("\u{feff}x\u{2066}", false).as_str(),
        r"\u{feff}x\u{2066}"
    );
}

#[test]
fn escape_keeps_ordinary_unicode() {
    assert_eq!(
        render::escape("Größe 日本 😀", false).as_str(),
        "Größe 日本 😀"
    );
}

#[test]
fn escape_keeps_newlines_and_tabs_only_when_multiline() {
    assert_eq!(render::escape("a\nb\tc", true).as_str(), "a\nb\tc");
    assert_eq!(render::escape("a\nb\tc", false).as_str(), r"a\x0ab\x09c");
    assert_eq!(render::escape("a\r\nb", true).as_str(), "a\\x0d\nb");
}

#[test]
fn masked_view_shows_every_field_with_hidden_ones_as_a_single_star() {
    let view = render::secret(&full_secret(), Reveal::Masked, &Utc);
    assert_eq!(
        view.as_str(),
        "\
title:         GitHub
username:      alice
password:      *
url:           https://github.com
tags:          work, dev
notes:         first line
               second line
region:        eu-west
recovery code: *"
    );
}

#[test]
fn shown_view_reveals_every_hidden_field() {
    let view = render::secret(&full_secret(), Reveal::Shown, &Utc);
    assert!(view.contains("password:      a-very-long-password-indeed\n"));
    assert!(view.ends_with("recovery code: 1234-5678"));
}

#[test]
fn shown_view_escapes_invisible_characters_and_backslashes_in_hidden_values() {
    let secret = Secret::new("GitHub")
        .with_password(hidden("zero\u{200b}width"))
        .with_custom_field(CustomField::hidden("pin", hidden(r"literal\xad")));
    let view = render::secret(&secret, Reveal::Shown, &Utc);
    assert!(view.contains(r"password: zero\u{200b}width"));
    assert!(view.ends_with(r"pin:      literal\\xad"));
}

#[test]
fn view_leaves_out_fields_that_are_not_set() {
    let view = render::secret(&Secret::new("bare"), Reveal::Masked, &Utc);
    assert_eq!(view.as_str(), "title: bare");
}

#[test]
fn view_escapes_stored_text_including_titles_and_field_names() {
    let crafted = Secret::new("evil\u{1b}]0;pwned\u{7}")
        .with_custom_field(CustomField::plain("x\u{202e}", "y"));
    let view = render::secret(&crafted, Reveal::Masked, &Utc);
    assert!(!view.contains('\u{1b}') && !view.contains('\u{202e}'));
    assert!(view.contains(r"evil\x1b]0;pwned\x07"));
    assert!(view.contains(r"x\u{202e}:"));
}

#[test]
fn saved_secret_view_shows_created_and_updated_times() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let password = MasterPassword::new("correct horse battery".into());
    let mut session = Session::create_insecure_for_tests(
        FileStore::new(dir.path())?,
        "alice",
        &password,
        SessionConfig::new(Arc::new(MemorySink::default())),
    )?;
    session.save(Secret::new("GitHub"))?;

    let view = render::secret(session.get("github")?, Reveal::Masked, &Utc);
    let lines: Vec<&str> = view.lines().collect();
    assert_eq!(lines.len(), 3);
    for (line, label) in lines[1..].iter().zip(["created: ", "updated: "]) {
        let time = line.strip_prefix(label).expect("label first");
        // YYYY-MM-DD HH:MM
        assert_eq!(time.len(), 16);
        assert_eq!(&time[4..5], "-");
        assert_eq!(&time[10..11], " ");
    }
    Ok(())
}

#[test]
fn list_shows_a_header_and_one_aligned_row_per_secret_without_hidden_fields() {
    let github = full_secret();
    let bare = Secret::new("wifi");
    let table = render::secret_list(&[&github, &bare]);
    assert_eq!(
        table.as_str(),
        "\
TITLE   USERNAME  URL                 TAGS
GitHub  alice     https://github.com  work, dev
wifi"
    );
    assert!(!table.contains("a-very-long-password-indeed"));
    assert!(!table.contains("1234-5678"));
    assert!(!table.contains("first line"));
}

#[test]
fn list_cuts_long_cells_short() {
    let long = Secret::new("site").with_url(format!("https://example.com/{}", "a".repeat(100)));
    let table = render::secret_list(&[&long]);
    let row = table.lines().nth(1).unwrap();
    // 32 columns: 20 for the prefix, 11 of the path, then the ellipsis
    assert!(row.ends_with(&format!("https://example.com/{}…", "a".repeat(11))));
}

#[test]
fn list_escapes_stored_text() {
    let crafted = Secret::new("a\u{1b}[31m").with_username("b\u{202e}");
    let table = render::secret_list(&[&crafted]);
    assert!(table.contains(r"a\x1b[31m"));
    assert!(table.contains(r"b\u{202e}"));
}

#[test]
fn empty_list_says_so() {
    assert_eq!(render::secret_list(&[]).as_str(), "no secrets yet");
}

/// `event` at Unix second `seconds`, as a readable log line.
///
/// ```text
/// render::audit_log(&[logged(0, Event::Locked)], &Utc)
/// ```
fn logged(seconds: i64, event: Event) -> Line {
    Line::Record(Record {
        time: DateTime::from_timestamp(seconds, 0).unwrap(),
        event,
    })
}

#[test]
fn audit_log_shows_one_line_per_event_with_time_and_title() {
    let lines = [
        logged(
            1_767_225_661,
            Event::SecretRevealed {
                title: "my bank".into(),
            },
        ),
        logged(1_767_225_600, Event::UnlockFailed),
        Line::Unreadable,
    ];
    assert_eq!(
        render::audit_log(&lines, &Utc).as_str(),
        "2026-01-01 00:01:01  secret revealed 'my bank'\n\
         2026-01-01 00:00:00  unlock failed (wrong master password)\n\
         <unreadable event>"
    );
}

#[test]
fn audit_log_escapes_titles_from_a_crafted_log() {
    let crafted = logged(
        0,
        Event::SecretRemoved {
            title: "evil\u{1b}[2J\u{202e}".into(),
        },
    );
    let text = render::audit_log(&[crafted], &Utc);
    assert!(!text.contains('\u{1b}') && !text.contains('\u{202e}'));
    assert!(text.ends_with(r"secret removed 'evil\x1b[2J\u{202e}'"));
}

#[test]
fn empty_audit_log_says_so() {
    assert_eq!(render::audit_log(&[], &Utc).as_str(), "no audit events yet");
}

/// The shared fixture of every audit event kind and how it is shown, also read by the
/// web client's tests so both front ends word events alike.
const AUDIT_EVENTS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../fixtures/audit-events.json"
));

/// A number per [`Event`] variant; exhaustive, so a new variant breaks the build here
/// until the fixture covers it.
///
/// ```text
/// assert_eq!(variant(&Event::Locked), 3);
/// ```
fn variant(event: &Event) -> usize {
    match event {
        Event::VaultCreated => 0,
        Event::Unlocked => 1,
        Event::UnlockFailed => 2,
        Event::Locked => 3,
        Event::AutoLocked => 4,
        Event::LockedOnConflict => 5,
        Event::TerminatedBySignal => 6,
        Event::SecretAdded { .. } => 7,
        Event::SecretReplaced { .. } => 8,
        Event::SecretRemoved { .. } => 9,
        Event::SecretRevealed { .. } => 10,
        Event::MasterPasswordChanged => 11,
        Event::MasterPasswordChangeFailed => 12,
        Event::BackupCreated { .. } => 13,
    }
}

#[test]
fn audit_log_words_every_event_kind_as_the_shared_fixture() {
    let fixture: Value = serde_json::from_str(AUDIT_EVENTS).unwrap();
    let mut seen = Vec::new();
    for case in fixture["events"].as_array().unwrap() {
        let event: Event = serde_json::from_value(case["event"].clone()).unwrap();
        seen.push(variant(&event));
        let title = event.title().map(|title| format!(" '{title}'"));
        let line = render::audit_log(&[logged(0, event)], &Utc);
        let shown = case["shown"].as_str().unwrap();
        assert_eq!(
            line.as_str(),
            format!("1970-01-01 00:00:00  {shown}{}", title.unwrap_or_default())
        );
    }
    seen.sort_unstable();
    assert_eq!(
        seen,
        (0..14).collect::<Vec<_>>(),
        "one fixture case per kind"
    );
}

#[test]
fn cause_kinds_are_worded_for_the_person() {
    assert_eq!(render::cause_kind(ErrorKind::StorageFull), "disk full");
    assert_eq!(
        render::cause_kind(ErrorKind::PermissionDenied),
        "permission denied"
    );
    assert_eq!(
        render::cause_kind(ErrorKind::ReadOnlyFilesystem),
        "read-only file system"
    );
    assert_eq!(
        render::cause_kind(LOCK_HELD_TOO_LONG),
        "vault is busy in another session"
    );
    assert_eq!(
        render::cause_kind(ErrorKind::NotFound),
        "unexpected file system error"
    );
}
