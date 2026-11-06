//! The text rules for secret fields (ADR-0013), through `Session`: unsafe characters
//! (from the shared fixture), length limits counted in characters, trimming and NFC,
//! title and duplicate matching, the URL forms, and stored secrets that break the rules.

use std::sync::Arc;

use serde_json::Value;
use tempfile::TempDir;
use vault_core::audit::MemorySink;
use vault_core::crypto::MasterPassword;
use vault_core::session::{
    self, CustomField, FieldProblem, FieldValue, HiddenValue, Saved, Secret, Session,
    SessionConfig, SessionError,
};
use vault_core::storage::FileStore;

const PASSWORD: &str = "correct horse battery";

/// The shared fixture of unsafe and safe characters, also read by the CLI and web tests.
const FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../fixtures/unsafe-characters.json"
));

/// A temporary vault home holding vault `alice`.
struct Fixture {
    dir: TempDir,
}

impl Fixture {
    /// A fresh vault home with no vaults.
    ///
    /// ```text
    /// let fx = Fixture::new();
    /// ```
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    /// A file store on the vault home.
    ///
    /// ```text
    /// session::insert_unchecked_for_tests(&fx.store(), "alice", &password(), secret)
    /// ```
    fn store(&self) -> FileStore {
        FileStore::new(self.dir.path()).unwrap()
    }

    /// Creates vault `alice` and returns its unlocked session.
    ///
    /// ```text
    /// let mut session = fx.create();
    /// ```
    fn create(&self) -> Session<FileStore> {
        Session::create_insecure_for_tests(self.store(), "alice", &password(), config()).unwrap()
    }

    /// Unlocks vault `alice`.
    ///
    /// ```text
    /// let mut session = fx.unlock();
    /// ```
    fn unlock(&self) -> Session<FileStore> {
        Session::unlock(self.store(), "alice", &password(), config()).unwrap()
    }
}

/// The master password of every test vault.
///
/// ```text
/// Session::unlock(store, "alice", &password(), config())
/// ```
fn password() -> MasterPassword {
    MasterPassword::new(PASSWORD.into())
}

/// A session config with an in-memory audit log.
///
/// ```text
/// Session::unlock(store, "alice", &password(), config())
/// ```
fn config() -> SessionConfig {
    SessionConfig::new(Arc::new(MemorySink::default()))
}

/// The problems of a refused save, `None` if it wasn't refused for its fields.
///
/// ```text
/// assert_eq!(problems(session.save(Secret::new(""))), Some(vec![FieldProblem::Title]));
/// ```
fn problems(result: Result<Saved, SessionError>) -> Option<Vec<FieldProblem>> {
    match result {
        Err(SessionError::InvalidSecret(invalid)) => Some(invalid.problems().to_vec()),
        _ => None,
    }
}

/// The text of a custom field, revealing it if hidden.
///
/// ```text
/// assert_eq!(field_text(&secret.custom_fields()[0]), "eu-west");
/// ```
fn field_text(field: &CustomField) -> &str {
    match field.value() {
        FieldValue::Plain(text) => text,
        FieldValue::Hidden(hidden) => hidden.reveal(),
    }
}

/// A character from a fixture code point such as `"202E"`.
///
/// ```text
/// assert_eq!(code_point("0041"), 'A');
/// ```
fn code_point(hex: &str) -> char {
    char::from_u32(u32::from_str_radix(hex, 16).unwrap()).unwrap()
}

/// Every unsafe character in the fixture, with whether it is a control character.
///
/// ```text
/// for (c, control) in unsafe_characters() { ... }
/// ```
fn unsafe_characters() -> Vec<(char, bool)> {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let mut out = Vec::new();
    for range in fixture["unsafe"].as_array().unwrap() {
        let from = u32::from(code_point(range["from"].as_str().unwrap()));
        let to = u32::from(code_point(range["to"].as_str().unwrap()));
        let control = range["control"].as_bool().unwrap();
        out.extend((from..=to).map(|c| (char::from_u32(c).unwrap(), control)));
    }
    out
}

/// The characters notes keep although they are unsafe elsewhere (newline and tab).
///
/// ```text
/// assert!(multiline_safe().contains(&'\n'));
/// ```
fn multiline_safe() -> Vec<char> {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    fixture["multiline_safe"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| code_point(c.as_str().unwrap()))
        .collect()
}

/// The safe look-alikes in the fixture.
///
/// ```text
/// for c in safe_characters() { ... }
/// ```
fn safe_characters() -> Vec<char> {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    fixture["safe"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| code_point(entry["char"].as_str().unwrap()))
        .collect()
}

/// A secret with `text` in the middle of every non-hidden field.
///
/// ```text
/// session.save(every_plain_field("a\u{200b}b"))
/// ```
fn every_plain_field(text: &str) -> Secret {
    Secret::new(format!("t{text}t"))
        .with_username(format!("u{text}u"))
        .with_url(format!("https://h{text}h.example"))
        .with_notes(format!("n{text}n"))
        .with_tag(format!("g{text}g"))
        .with_custom_field(CustomField::plain(format!("f{text}f"), format!("v{text}v")))
}

#[test]
fn the_fixture_is_well_formed_and_the_core_refuses_exactly_its_unsafe_characters() {
    let unsafe_chars = unsafe_characters();
    assert!(unsafe_chars.len() > 200);
    for (c, control) in &unsafe_chars {
        assert!(
            session::is_unsafe_char(*c, false),
            "U+{:04X}",
            u32::from(*c)
        );
        assert_eq!(c.is_control(), *control, "U+{:04X}", u32::from(*c));
    }
    for c in multiline_safe() {
        assert!(session::is_unsafe_char(c, false));
        assert!(!session::is_unsafe_char(c, true));
    }
    for c in safe_characters() {
        assert!(!session::is_unsafe_char(c, false), "U+{:04X}", u32::from(c));
    }
}

#[test]
fn every_unsafe_character_is_refused_in_every_non_hidden_field() {
    let fx = Fixture::new();
    let mut session = fx.create();
    let multiline = multiline_safe();
    for (c, _) in unsafe_characters() {
        let found = problems(session.save(every_plain_field(&c.to_string())));
        let mut expected = vec![
            FieldProblem::Title,
            FieldProblem::Username,
            FieldProblem::Url,
        ];
        if !multiline.contains(&c) {
            expected.push(FieldProblem::Notes);
        }
        expected.extend([
            FieldProblem::Tag(0),
            FieldProblem::CustomFieldName(0),
            FieldProblem::CustomFieldValue(0),
        ]);
        assert_eq!(found, Some(expected), "U+{:04X}", u32::from(c));
    }
    assert!(session.list().unwrap().is_empty());
}

#[test]
fn hidden_fields_refuse_only_control_characters_and_keep_the_rest_byte_for_byte() {
    let fx = Fixture::new();
    let mut session = fx.create();
    for (c, control) in unsafe_characters() {
        let value = format!("p{c}p");
        let secret = Secret::new("t")
            .with_password(HiddenValue::new(value.clone()))
            .with_custom_field(CustomField::hidden("pin", HiddenValue::new(value.clone())));
        let result = session.save(secret);
        if control {
            assert_eq!(
                problems(result),
                Some(vec![
                    FieldProblem::Password,
                    FieldProblem::CustomFieldValue(0)
                ]),
                "U+{:04X}",
                u32::from(c)
            );
        } else {
            assert!(result.is_ok(), "U+{:04X}", u32::from(c));
            let stored = session.get("t").unwrap();
            assert_eq!(stored.password().unwrap().reveal(), value);
            assert_eq!(field_text(&stored.custom_fields()[0]), value);
        }
    }
}

#[test]
fn safe_look_alikes_are_accepted_in_every_free_text_field() {
    let fx = Fixture::new();
    let mut session = fx.create();
    for c in safe_characters() {
        let text = c.to_string();
        // The URL has its own form rule, so it keeps a plain host here.
        let secret = every_plain_field(&text)
            .with_url("github.com")
            .with_password(HiddenValue::new(format!("p{c}p")))
            .with_custom_field(CustomField::hidden("pin", HiddenValue::new(text.clone())));
        assert!(session.save(secret).is_ok(), "U+{:04X}", u32::from(c));
    }
}

#[test]
fn notes_accept_newline_and_tab_and_refuse_carriage_return() {
    let fx = Fixture::new();
    let mut session = fx.create();
    assert_eq!(
        session.save(Secret::new("t").with_notes("line 1\n\tline 2")),
        Ok(Saved::Added)
    );
    assert_eq!(
        problems(session.save(Secret::new("t").with_notes("line 1\r\nline 2"))),
        Some(vec![FieldProblem::Notes])
    );
}

/// Character-counted limits: (field, max, secret with `n` multi-byte characters in it,
/// problem when over).
type Boundary = (&'static str, usize, fn(usize) -> Secret, FieldProblem);

#[test]
fn every_field_accepts_its_maximum_in_characters_and_refuses_one_more() {
    let wide = |n: usize| "é".repeat(n);
    let boundaries: [Boundary; 9] = [
        (
            "title",
            64,
            |n| Secret::new("é".repeat(n)),
            FieldProblem::Title,
        ),
        (
            "username",
            256,
            |n| Secret::new("t").with_username("é".repeat(n)),
            FieldProblem::Username,
        ),
        (
            "password",
            1024,
            |n| Secret::new("t").with_password(HiddenValue::new("😀".repeat(n))),
            FieldProblem::Password,
        ),
        (
            "url",
            2048,
            |n| Secret::new("t").with_url(format!("https://{}", "é".repeat(n - 8))),
            FieldProblem::Url,
        ),
        (
            "notes",
            4096,
            |n| Secret::new("t").with_notes("é".repeat(n)),
            FieldProblem::Notes,
        ),
        (
            "tag",
            32,
            |n| Secret::new("t").with_tag("é".repeat(n)),
            FieldProblem::Tag(0),
        ),
        (
            "custom field name",
            64,
            |n| Secret::new("t").with_custom_field(CustomField::plain("é".repeat(n), "v")),
            FieldProblem::CustomFieldName(0),
        ),
        (
            "plain custom field value",
            1024,
            |n| Secret::new("t").with_custom_field(CustomField::plain("f", "é".repeat(n))),
            FieldProblem::CustomFieldValue(0),
        ),
        (
            "hidden custom field value",
            1024,
            |n| {
                Secret::new("t")
                    .with_custom_field(CustomField::hidden("f", HiddenValue::new("😀".repeat(n))))
            },
            FieldProblem::CustomFieldValue(0),
        ),
    ];
    assert_eq!(wide(2).len(), 4, "multi-byte input");
    let fx = Fixture::new();
    let mut session = fx.create();
    for (field, max, secret, problem) in boundaries {
        assert!(session.save(secret(max)).is_ok(), "{field} at {max}");
        assert_eq!(
            problems(session.save(secret(max + 1))),
            Some(vec![problem]),
            "{field} at {}",
            max + 1
        );
    }
}

#[test]
fn a_secret_holds_32_tags_and_32_custom_fields_but_not_33() {
    let with = |n: usize| {
        let secret = (0..n).fold(Secret::new("t"), |s, i| s.with_tag(format!("t{i}")));
        (0..n).fold(secret, |s, i| {
            s.with_custom_field(CustomField::plain(format!("f{i}"), "v"))
        })
    };
    let fx = Fixture::new();
    let mut session = fx.create();
    assert!(session.save(with(32)).is_ok());
    assert_eq!(
        problems(session.save(with(33))),
        Some(vec![
            FieldProblem::TooManyTags,
            FieldProblem::TooManyCustomFields
        ])
    );
}

#[test]
fn single_line_fields_are_trimmed_and_notes_and_hidden_fields_are_not() {
    let fx = Fixture::new();
    let mut session = fx.create();
    let secret = Secret::new("  GitHub\u{a0}")
        .with_username(" alice ")
        .with_password(HiddenValue::new("  p4ss  ".into()))
        .with_url("\thttps://github.com ")
        .with_notes("  indented\n")
        .with_tag(" work ")
        .with_custom_field(CustomField::plain(" region ", " eu-west "))
        .with_custom_field(CustomField::hidden(
            " pin ",
            HiddenValue::new(" 1234 ".into()),
        ));
    session.save(secret).unwrap();
    session.lock();

    let mut session = fx.unlock();
    let github = session.get("github").unwrap();
    assert_eq!(github.title(), "GitHub");
    assert_eq!(github.username(), Some("alice"));
    assert_eq!(github.password().unwrap().reveal(), "  p4ss  ");
    assert_eq!(github.url(), Some("https://github.com"));
    assert_eq!(github.notes(), Some("  indented\n"));
    assert_eq!(github.tags().collect::<Vec<_>>(), ["work"]);
    let fields = github.custom_fields();
    assert_eq!(fields[0].name(), "region");
    assert_eq!(field_text(&fields[0]), "eu-west");
    assert_eq!(fields[1].name(), "pin");
    assert_eq!(field_text(&fields[1]), " 1234 ");
}

#[test]
fn whitespace_only_single_line_fields_are_refused() {
    let fx = Fixture::new();
    let mut session = fx.create();
    let secret = Secret::new(" \u{3000} ")
        .with_username("  ")
        .with_url(" ")
        .with_tag("work")
        .with_tag("   ")
        .with_custom_field(CustomField::plain("  ", "v"))
        .with_custom_field(CustomField::plain("f", "  "));
    assert_eq!(
        problems(session.save(secret)),
        Some(vec![
            FieldProblem::Title,
            FieldProblem::Username,
            FieldProblem::Url,
            FieldProblem::Tag(1),
            FieldProblem::CustomFieldName(0),
            FieldProblem::CustomFieldValue(1),
        ])
    );
}

#[test]
fn composed_and_decomposed_titles_are_one_secret() {
    let composed = "Caf\u{e9}";
    let decomposed = "Cafe\u{301}";
    let fx = Fixture::new();
    let mut session = fx.create();

    assert_eq!(session.save(Secret::new(decomposed)), Ok(Saved::Added));
    assert_eq!(session.get(composed).unwrap().title(), composed);
    assert_eq!(session.get(" CAFE\u{301} ").unwrap().title(), composed);
    assert!(session.contains(decomposed).unwrap());
    assert_eq!(
        session.save(Secret::new(composed).with_username("alice")),
        Ok(Saved::Replaced)
    );
    let shown = session
        .reveal(decomposed, |secret| {
            Ok::<_, SessionError>(secret.username().map(str::to_owned))
        })
        .unwrap();
    assert_eq!(shown.as_deref(), Some("alice"));
    assert_eq!(session.list().unwrap().len(), 1);
    session.remove(decomposed).unwrap();
    assert!(session.list().unwrap().is_empty());
}

#[test]
fn non_hidden_fields_are_stored_nfc_normalised() {
    let fx = Fixture::new();
    let mut session = fx.create();
    let secret = Secret::new("t")
        .with_username("jose\u{301}")
        .with_notes("cafe\u{301}\n")
        .with_tag("re\u{301}sume\u{301}")
        .with_custom_field(CustomField::plain("re\u{301}gion", "ve\u{301}"));
    session.save(secret).unwrap();
    let stored = session.get("t").unwrap();
    assert_eq!(stored.username(), Some("jos\u{e9}"));
    assert_eq!(stored.notes(), Some("caf\u{e9}\n"));
    assert_eq!(stored.tags().collect::<Vec<_>>(), ["r\u{e9}sum\u{e9}"]);
    assert_eq!(stored.custom_fields()[0].name(), "r\u{e9}gion");
    assert_eq!(field_text(&stored.custom_fields()[0]), "v\u{e9}");
}

#[test]
fn nfc_equal_tags_and_custom_field_names_are_duplicates() {
    let fx = Fixture::new();
    let mut session = fx.create();
    let secret = Secret::new("t")
        .with_tag("caf\u{e9}")
        .with_tag(" CAFE\u{301}")
        .with_tag(" work")
        .with_tag("work")
        .with_custom_field(CustomField::plain("r\u{e9}gion", "a"))
        .with_custom_field(CustomField::hidden(
            "RE\u{301}GION ",
            HiddenValue::new("b".into()),
        ));
    assert_eq!(
        problems(session.save(secret)),
        Some(vec![
            FieldProblem::DuplicateTag(1),
            FieldProblem::DuplicateTag(3),
            FieldProblem::DuplicateCustomFieldName(1),
        ])
    );
}

#[test]
fn hidden_values_come_back_byte_for_byte_after_lock_and_unlock() {
    let value = " cafe\u{301} \u{200b}x ";
    let fx = Fixture::new();
    let mut session = fx.create();
    session
        .save(
            Secret::new("t")
                .with_password(HiddenValue::new(value.into()))
                .with_custom_field(CustomField::hidden("seed", HiddenValue::new(value.into()))),
        )
        .unwrap();
    session.lock();

    let mut session = fx.unlock();
    let stored = session.get("t").unwrap();
    assert_eq!(
        stored.password().unwrap().reveal().as_bytes(),
        value.as_bytes()
    );
    assert_eq!(
        field_text(&stored.custom_fields()[0]).as_bytes(),
        value.as_bytes()
    );
}

#[test]
fn urls_must_be_http_or_https_with_a_host_or_a_bare_host() {
    let fx = Fixture::new();
    let mut session = fx.create();
    for url in [
        "https://github.com/x",
        "http://localhost:8080",
        "HTTPS://GitHub.com",
        "https://alice@[::1]:8443/path?q=1#top",
        "github.com",
        "localhost",
        "github.com/login?next=%2F",
        "intranet:8080/wiki",
    ] {
        session.save(Secret::new("t").with_url(url)).unwrap();
        assert_eq!(session.get("t").unwrap().url(), Some(url), "{url}");
    }
    for url in [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "file:///etc",
        "ssh://host",
        "https://",
        "https:///path",
        "http://:8080",
        "https://user@/x",
        "https:github.com",
        "//github.com",
        "mailto:alice@example.com",
        "https://git hub.com",
        "github.com:ssh",
        ".github.com",
        "github..com",
    ] {
        assert_eq!(
            problems(session.save(Secret::new("t").with_url(url))),
            Some(vec![FieldProblem::UnsupportedUrl]),
            "{url}"
        );
    }
}

#[test]
fn the_url_message_names_the_accepted_forms_and_the_alternatives() {
    let message = FieldProblem::UnsupportedUrl.to_string();
    for part in ["http://", "https://", "github.com", "notes", "custom field"] {
        assert!(message.contains(part), "{message}");
    }
}

#[test]
fn a_stored_secret_breaking_the_rules_opens_lists_reveals_and_deletes_but_cannot_be_saved() {
    let title = "evil\u{202e}gpj.exe";
    let fx = Fixture::new();
    fx.create().lock();
    let stored = Secret::new(title)
        .with_username(" spaced ")
        .with_url("javascript:alert(1)")
        .with_password(HiddenValue::new("s3cret!".into()));
    session::insert_unchecked_for_tests(&fx.store(), "alice", &password(), stored).unwrap();

    let mut session = fx.unlock();
    let titles: Vec<_> = session.list().unwrap().iter().map(|s| s.title()).collect();
    assert_eq!(titles, [title]);
    assert_eq!(
        session.get(title).unwrap().url(),
        Some("javascript:alert(1)")
    );
    let revealed = session
        .reveal(title, |secret| {
            Ok::<_, SessionError>(secret.password().map(|p| p.reveal().to_owned()))
        })
        .unwrap();
    assert_eq!(revealed.as_deref(), Some("s3cret!"));

    let resave = Secret::new(title)
        .with_username(" spaced ")
        .with_url("javascript:alert(1)");
    assert_eq!(
        problems(session.save(resave)),
        Some(vec![FieldProblem::Title, FieldProblem::UnsupportedUrl])
    );
    session.remove(title).unwrap();
    assert!(session.list().unwrap().is_empty());
}
