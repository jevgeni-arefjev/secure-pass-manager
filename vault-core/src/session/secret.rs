//! The secret model: a title, the standard fields, custom fields and timestamps, with
//! the validation every saved secret must pass and its JSON form inside the body.
//!
//! Security: hidden values live in page-locked, zeroizing memory ([`HiddenValue`]);
//! every other field is a [`Zeroizing`] string, wiped when dropped but not locked.
//! Nothing here implements `Debug`, `Display` or `Clone`, so a hidden value can only
//! leave through an explicit [`HiddenValue::reveal`].

use std::fmt;

use serde::de::{self, Deserializer, Visitor};
use serde::ser::{SerializeStruct, Serializer};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::LockedBytes;

pub mod check;
mod invalid;
mod text;
mod url;

pub use invalid::{CustomFieldPart, FieldProblem, InvalidSecret, SecretField};
pub use text::is_unsafe_char;

/// Longest title, in characters.
const MAX_TITLE: usize = 64;
/// Longest username, in characters.
const MAX_USERNAME: usize = 256;
/// Longest URL, in characters.
const MAX_URL: usize = 2048;
/// Longest password or other hidden value, in characters.
const MAX_HIDDEN: usize = 1024;
/// Longest notes, in characters.
const MAX_NOTES: usize = 4096;
/// Most tags on one secret.
const MAX_TAGS: usize = 32;
/// Longest tag, in characters.
const MAX_TAG: usize = 32;
/// Most custom fields on one secret.
const MAX_CUSTOM_FIELDS: usize = 32;
/// Longest custom field name, in characters.
const MAX_FIELD_NAME: usize = 64;
/// Longest non-hidden custom field value, in characters.
const MAX_FIELD_VALUE: usize = 1024;

/// Names of the standard fields; a custom field can't take one of them.
const STANDARD_FIELD_NAMES: &[&str] = &["title", "username", "password", "url", "notes", "tags"];

/// A hidden field's value: a password, token, key or seed, kept in page-locked memory
/// and zeroized when dropped.
///
/// Security: no `Debug`, `Display` or `Clone`; the text is only reachable through
/// [`HiddenValue::reveal`]. Build it straight from a hidden prompt.
///
/// ```
/// use vault_core::session::HiddenValue;
/// let password = HiddenValue::new(String::from("s3cret!"));
/// assert_eq!(password.reveal(), "s3cret!");
/// ```
///
/// It can't be copied or printed; these must fail to compile:
///
/// ```compile_fail
/// # use vault_core::session::HiddenValue;
/// let _copy = HiddenValue::new(String::from("s3cret!")).clone();
/// ```
///
/// ```compile_fail
/// # use vault_core::session::HiddenValue;
/// println!("{:?}", HiddenValue::new(String::from("s3cret!")));
/// ```
pub struct HiddenValue(LockedBytes);

impl HiddenValue {
    /// Moves `value` into locked memory and zeroizes the original string.
    ///
    /// ```
    /// # use vault_core::session::HiddenValue;
    /// let token = HiddenValue::new(String::from("ghp_example"));
    /// ```
    #[must_use]
    pub fn new(mut value: String) -> Self {
        let locked = LockedBytes::from_slice(value.as_bytes());
        value.zeroize();
        Self(locked)
    }

    /// The value as text. Security: call it only to show or copy one value the person
    /// explicitly asked for, and don't keep the result around.
    ///
    /// ```
    /// # use vault_core::session::HiddenValue;
    /// let password = HiddenValue::new(String::from("s3cret!"));
    /// assert_eq!(password.reveal(), "s3cret!");
    /// ```
    #[must_use]
    pub fn reveal(&self) -> &str {
        std::str::from_utf8(self.0.as_bytes()).expect("built from a str")
    }

    /// Whether the value's memory is locked out of swap (false means zeroize-only).
    ///
    /// ```
    /// # use vault_core::session::HiddenValue;
    /// let _locked = HiddenValue::new(String::from("s3cret!")).is_memory_locked();
    /// ```
    #[must_use]
    pub fn is_memory_locked(&self) -> bool {
        self.0.is_locked()
    }
}

impl Serialize for HiddenValue {
    /// Writes the value as a JSON string, into the body only.
    ///
    /// ```ignore
    /// serde_json::to_writer(&mut zeroizing_buffer, &hidden)?;
    /// ```
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.reveal())
    }
}

impl<'de> Deserialize<'de> for HiddenValue {
    /// Reads a JSON string straight into locked memory. An unescaped string is copied
    /// from the (locked) body without an intermediate `String`.
    ///
    /// ```ignore
    /// let hidden: HiddenValue = serde_json::from_slice(br#""s3cret!""#)?;
    /// ```
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// Builds a [`HiddenValue`] from whichever form of string the parser hands over.
        struct HiddenVisitor;

        impl Visitor<'_> for HiddenVisitor {
            type Value = HiddenValue;

            /// Describes the expected input for parse errors.
            ///
            /// ```ignore
            /// // "invalid type: integer `1`, expected a string"
            /// ```
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string")
            }

            /// Copies a borrowed string into locked memory.
            ///
            /// ```ignore
            /// HiddenVisitor.visit_str::<serde_json::Error>("s3cret!")
            /// ```
            fn visit_str<E: de::Error>(self, value: &str) -> Result<HiddenValue, E> {
                Ok(HiddenValue(LockedBytes::from_slice(value.as_bytes())))
            }

            /// Moves an owned string into locked memory, zeroizing it.
            ///
            /// ```ignore
            /// HiddenVisitor.visit_string::<serde_json::Error>(String::from("s3cret!"))
            /// ```
            fn visit_string<E: de::Error>(self, value: String) -> Result<HiddenValue, E> {
                Ok(HiddenValue::new(value))
            }
        }

        deserializer.deserialize_str(HiddenVisitor)
    }
}

/// The value of a custom field: shown normally, or hidden like a password.
///
/// ```
/// use vault_core::session::{FieldValue, HiddenValue};
/// let code = FieldValue::Hidden(HiddenValue::new("1234-5678".into()));
/// assert!(code.is_hidden());
/// ```
pub enum FieldValue {
    /// Shown in lists and views.
    Plain(Zeroizing<String>),
    /// A hidden field: masked unless explicitly revealed.
    Hidden(HiddenValue),
}

impl FieldValue {
    /// Whether this is a hidden field.
    ///
    /// ```
    /// # use vault_core::session::FieldValue;
    /// assert!(!FieldValue::Plain(String::from("eu-west").into()).is_hidden());
    /// ```
    #[must_use]
    pub fn is_hidden(&self) -> bool {
        matches!(self, Self::Hidden(_))
    }
}

/// A field the person names themselves, beyond the standard ones (e.g. a recovery code).
///
/// ```
/// use vault_core::session::{CustomField, HiddenValue};
/// let field = CustomField::hidden("recovery code", HiddenValue::new("1234-5678".into()));
/// assert_eq!(field.name(), "recovery code");
/// ```
pub struct CustomField {
    /// The name, as the person wrote it (normalised on save).
    name: Zeroizing<String>,
    /// The value, plain or hidden.
    value: FieldValue,
}

impl CustomField {
    /// A custom field with a value that is plain or hidden, e.g. one already checked
    /// with [`check::custom_field_value`].
    ///
    /// ```
    /// # use vault_core::session::{CustomField, FieldValue, HiddenValue};
    /// let value = FieldValue::Hidden(HiddenValue::new("1234".into()));
    /// assert!(CustomField::new("pin", value).value().is_hidden());
    /// ```
    #[must_use]
    pub fn new(name: impl Into<String>, value: FieldValue) -> Self {
        Self {
            name: Zeroizing::new(name.into()),
            value,
        }
    }

    /// A custom field shown normally.
    ///
    /// ```
    /// # use vault_core::session::CustomField;
    /// let region = CustomField::plain("region", "eu-west");
    /// assert!(!region.value().is_hidden());
    /// ```
    #[must_use]
    pub fn plain(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self::new(name, FieldValue::Plain(Zeroizing::new(value.into())))
    }

    /// A hidden custom field.
    ///
    /// ```
    /// # use vault_core::session::{CustomField, HiddenValue};
    /// let seed = CustomField::hidden("totp seed", HiddenValue::new("JBSWY3DP".into()));
    /// assert!(seed.value().is_hidden());
    /// ```
    #[must_use]
    pub fn hidden(name: impl Into<String>, value: HiddenValue) -> Self {
        Self::new(name, FieldValue::Hidden(value))
    }

    /// The field's name, as the person wrote it.
    ///
    /// ```
    /// # use vault_core::session::CustomField;
    /// assert_eq!(CustomField::plain("region", "eu").name(), "region");
    /// ```
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The field's value.
    ///
    /// ```
    /// # use vault_core::session::{CustomField, FieldValue};
    /// if let FieldValue::Plain(text) = CustomField::plain("region", "eu").value() {
    ///     assert_eq!(text.as_str(), "eu");
    /// }
    /// ```
    #[must_use]
    pub fn value(&self) -> &FieldValue {
        &self.value
    }
}

impl Serialize for CustomField {
    /// Writes `{"name", "hidden", "value"}`; a hidden value goes straight from locked
    /// memory into the body.
    ///
    /// ```ignore
    /// // {"name":"recovery code","hidden":true,"value":"1234-5678"}
    /// ```
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut out = serializer.serialize_struct("CustomField", 3)?;
        out.serialize_field("name", self.name.as_str())?;
        match &self.value {
            FieldValue::Plain(text) => {
                out.serialize_field("hidden", &false)?;
                out.serialize_field("value", text.as_str())?;
            }
            FieldValue::Hidden(hidden) => {
                out.serialize_field("hidden", &true)?;
                out.serialize_field("value", hidden)?;
            }
        }
        out.end()
    }
}

impl<'de> Deserialize<'de> for CustomField {
    /// Reads `{"name", "hidden", "value"}`. The value is read into locked memory first,
    /// and only copied out when the field turns out not to be hidden.
    ///
    /// ```ignore
    /// let field: CustomField = serde_json::from_slice(br#"{"name":"a","hidden":true,"value":"b"}"#)?;
    /// ```
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// The stored form, before the value is sorted into plain or hidden.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Stored {
            name: Zeroizing<String>,
            hidden: bool,
            value: HiddenValue,
        }

        let Stored {
            name,
            hidden,
            value,
        } = Stored::deserialize(deserializer)?;
        let value = if hidden {
            FieldValue::Hidden(value)
        } else {
            FieldValue::Plain(Zeroizing::new(value.reveal().to_owned()))
        };
        Ok(Self { name, value })
    }
}

/// Everything needed to access one service. Built by a front end with [`Secret::new`]
/// and the `with_*` methods, then handed to the session to save; the session checks
/// it and sets its timestamps.
///
/// ```
/// use vault_core::session::{HiddenValue, Secret};
///
/// let github = Secret::new("GitHub")
///     .with_username("alice")
///     .with_password(HiddenValue::new("s3cret!".into()))
///     .with_url("https://github.com")
///     .with_tag("work");
/// assert_eq!(github.username(), Some("alice"));
/// ```
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Secret {
    /// The title that identifies this secret in its vault.
    title: Zeroizing<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The username, if set.
    username: Option<Zeroizing<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The password, if set; in locked memory.
    password: Option<HiddenValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The URL, if set.
    url: Option<Zeroizing<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The notes, if set; may span several lines.
    notes: Option<Zeroizing<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// The tags, in the order they were added.
    tags: Vec<Zeroizing<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// The custom fields, in the order they were added.
    custom_fields: Vec<CustomField>,
    /// When the secret was first saved, in Unix seconds; 0 before that.
    created_at: u64,
    /// When the secret was last saved, in Unix seconds; 0 before that.
    updated_at: u64,
}

impl Secret {
    /// A new secret with only a title. When it is saved, the title (like every other
    /// single-line non-hidden field) is trimmed and NFC-normalised.
    ///
    /// ```
    /// # use vault_core::session::Secret;
    /// assert_eq!(Secret::new("GitHub").title(), "GitHub");
    /// ```
    #[must_use]
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: Zeroizing::new(title.into()),
            username: None,
            password: None,
            url: None,
            notes: None,
            tags: Vec::new(),
            custom_fields: Vec::new(),
            created_at: 0,
            updated_at: 0,
        }
    }

    /// Sets the username.
    ///
    /// ```
    /// # use vault_core::session::Secret;
    /// assert_eq!(Secret::new("GitHub").with_username("alice").username(), Some("alice"));
    /// ```
    #[must_use]
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(Zeroizing::new(username.into()));
        self
    }

    /// Sets the password, which is always a hidden field.
    ///
    /// ```
    /// # use vault_core::session::{HiddenValue, Secret};
    /// let secret = Secret::new("GitHub").with_password(HiddenValue::new("s3cret!".into()));
    /// assert!(secret.password().is_some());
    /// ```
    #[must_use]
    pub fn with_password(mut self, password: HiddenValue) -> Self {
        self.password = Some(password);
        self
    }

    /// Sets the URL: an `http` or `https` URL with a host, or a bare host such as
    /// `github.com`. It is stored as typed (trimmed and NFC-normalised), never rewritten.
    ///
    /// ```
    /// # use vault_core::session::Secret;
    /// let secret = Secret::new("GitHub").with_url("https://github.com");
    /// assert_eq!(secret.url(), Some("https://github.com"));
    /// ```
    #[must_use]
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(Zeroizing::new(url.into()));
        self
    }

    /// Sets the notes, which may span several lines.
    ///
    /// ```
    /// # use vault_core::session::Secret;
    /// let secret = Secret::new("GitHub").with_notes("2FA on\nbackup codes in safe");
    /// assert!(secret.notes().is_some());
    /// ```
    #[must_use]
    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = Some(Zeroizing::new(notes.into()));
        self
    }

    /// Adds a tag.
    ///
    /// ```
    /// # use vault_core::session::Secret;
    /// let secret = Secret::new("GitHub").with_tag("work").with_tag("dev");
    /// assert_eq!(secret.tags().collect::<Vec<_>>(), ["work", "dev"]);
    /// ```
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(Zeroizing::new(tag.into()));
        self
    }

    /// Adds a custom field.
    ///
    /// ```
    /// # use vault_core::session::{CustomField, Secret};
    /// let secret = Secret::new("AWS").with_custom_field(CustomField::plain("region", "eu"));
    /// assert_eq!(secret.custom_fields().len(), 1);
    /// ```
    #[must_use]
    pub fn with_custom_field(mut self, field: CustomField) -> Self {
        self.custom_fields.push(field);
        self
    }

    /// The title that identifies this secret in its vault.
    ///
    /// ```
    /// # use vault_core::session::Secret;
    /// assert_eq!(Secret::new("GitHub").title(), "GitHub");
    /// ```
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// The username, if set.
    ///
    /// ```
    /// # use vault_core::session::Secret;
    /// assert_eq!(Secret::new("GitHub").username(), None);
    /// ```
    #[must_use]
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref().map(String::as_str)
    }

    /// The password, if set. Masked until [`HiddenValue::reveal`] is called.
    ///
    /// ```
    /// # use vault_core::session::{HiddenValue, Secret};
    /// let secret = Secret::new("GitHub").with_password(HiddenValue::new("s3cret!".into()));
    /// assert_eq!(secret.password().map(HiddenValue::reveal), Some("s3cret!"));
    /// ```
    #[must_use]
    pub fn password(&self) -> Option<&HiddenValue> {
        self.password.as_ref()
    }

    /// The URL, if set.
    ///
    /// ```
    /// # use vault_core::session::Secret;
    /// assert_eq!(Secret::new("GitHub").url(), None);
    /// ```
    #[must_use]
    pub fn url(&self) -> Option<&str> {
        self.url.as_deref().map(String::as_str)
    }

    /// The notes, if set.
    ///
    /// ```
    /// # use vault_core::session::Secret;
    /// assert_eq!(Secret::new("GitHub").with_notes("hi").notes(), Some("hi"));
    /// ```
    #[must_use]
    pub fn notes(&self) -> Option<&str> {
        self.notes.as_deref().map(String::as_str)
    }

    /// The tags, in the order they were added.
    ///
    /// ```
    /// # use vault_core::session::Secret;
    /// assert_eq!(Secret::new("GitHub").tags().count(), 0);
    /// ```
    pub fn tags(&self) -> impl Iterator<Item = &str> {
        self.tags.iter().map(|tag| tag.as_str())
    }

    /// The custom fields, in the order they were added.
    ///
    /// ```
    /// # use vault_core::session::Secret;
    /// assert!(Secret::new("GitHub").custom_fields().is_empty());
    /// ```
    #[must_use]
    pub fn custom_fields(&self) -> &[CustomField] {
        &self.custom_fields
    }

    /// When the secret was first saved, in Unix seconds; 0 before it is saved.
    ///
    /// ```
    /// # use vault_core::session::Secret;
    /// assert_eq!(Secret::new("GitHub").created_at(), 0);
    /// ```
    #[must_use]
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// When the secret was last saved, in Unix seconds; 0 before it is saved.
    ///
    /// ```
    /// # use vault_core::session::Secret;
    /// assert_eq!(Secret::new("GitHub").updated_at(), 0);
    /// ```
    #[must_use]
    pub fn updated_at(&self) -> u64 {
        self.updated_at
    }

    /// Whether this secret's title matches `title`, ignoring case, surrounding spaces
    /// and Unicode composition (NFC).
    ///
    /// ```ignore
    /// assert!(Secret::new("Caf\u{e9}").has_title(" CAFE\u{301}"));
    /// ```
    pub(super) fn has_title(&self, title: &str) -> bool {
        text::same_folded(&self.title, title)
    }

    /// Orders secrets by title, ignoring case and Unicode composition, for listing.
    ///
    /// ```ignore
    /// secrets.sort_by(|a, b| a.cmp_title(b));
    /// ```
    pub(super) fn cmp_title(&self, other: &Self) -> std::cmp::Ordering {
        text::folded(&self.title).cmp(text::folded(&other.title))
    }

    /// Sets the timestamps of a save at `now`, keeping `created_at` from the secret
    /// this one replaces.
    ///
    /// ```ignore
    /// secret.stamp(replaced.map(Secret::created_at), clock.unix_time());
    /// ```
    pub(super) fn stamp(&mut self, created_at: Option<u64>, now: u64) {
        self.created_at = created_at.unwrap_or(now);
        self.updated_at = now;
    }

    /// Whether every hidden value is in locked memory.
    ///
    /// ```ignore
    /// if !secret.is_memory_locked() { /* warn */ }
    /// ```
    pub(super) fn is_memory_locked(&self) -> bool {
        let custom_hidden = self
            .custom_fields
            .iter()
            .filter_map(|field| match &field.value {
                FieldValue::Hidden(hidden) => Some(hidden),
                FieldValue::Plain(_) => None,
            });
        self.password
            .iter()
            .chain(custom_hidden)
            .all(HiddenValue::is_memory_locked)
    }

    /// Puts every non-hidden field into its stored form (trimmed and NFC-normalised; notes only
    /// NFC-normalised) and checks every field against the rules on [`FieldProblem`], collecting
    /// every problem rather than stopping at the first. Hidden fields are left as
    /// entered.
    /// Each field goes through its [`check`] function, the same one a front end uses to
    /// check an answer as it is entered; the tag and custom field counts are checked
    /// only here.
    ///
    /// Security: this is where control, format and separator characters are refused
    /// (hidden fields: control characters only), so nothing saved can drive a terminal
    /// or disguise itself when it is shown later. Problems name the field, never the
    /// value.
    ///
    /// ```ignore
    /// secret.validate()?;
    /// ```
    pub(super) fn validate(&mut self) -> Result<(), InvalidSecret> {
        self.normalize();
        let optional = |text: Option<&str>, rule: fn(&str) -> Result<(), FieldProblem>| {
            text.and_then(|text| rule(text).err())
        };
        let mut problems: Vec<FieldProblem> = [
            check::title(&self.title).err(),
            optional(self.username(), check::username),
            self.password()
                .and_then(|password| check::password(password).err()),
            optional(self.url(), check::url),
            optional(self.notes(), check::notes),
        ]
        .into_iter()
        .flatten()
        .collect();
        self.check_tags(&mut problems);
        self.check_custom_fields(&mut problems);
        InvalidSecret::from_problems(problems)
    }

    /// Trims and NFC-normalises every non-hidden field in place; notes are NFC-normalised only.
    ///
    /// ```ignore
    /// self.normalize(); // " Cafe\u{301} " is now "Caf\u{e9}"
    /// ```
    fn normalize(&mut self) {
        text::normalize_single_line(&mut self.title);
        for field in [&mut self.username, &mut self.url].into_iter().flatten() {
            text::normalize_single_line(field);
        }
        if let Some(notes) = &mut self.notes {
            text::normalize_notes(notes);
        }
        for tag in &mut self.tags {
            text::normalize_single_line(tag);
        }
        for field in &mut self.custom_fields {
            text::normalize_single_line(&mut field.name);
            if let FieldValue::Plain(value) = &mut field.value {
                text::normalize_single_line(value);
            }
        }
    }

    /// Adds to `problems` a too-high tag count, each broken tag, and each tag that
    /// repeats an earlier one (ignoring case and Unicode composition).
    ///
    /// ```ignore
    /// self.check_tags(&mut problems);
    /// ```
    fn check_tags(&self, problems: &mut Vec<FieldProblem>) {
        if self.tags.len() > MAX_TAGS {
            problems.push(FieldProblem::TooManyTags);
        }
        for (i, tag) in self.tags.iter().enumerate() {
            problems.extend(check::tag(tag, &self.tags[..i]).err());
        }
    }

    /// Adds to `problems` a too-high custom field count, each broken name and value,
    /// and each name that repeats an earlier one or a standard field name (ignoring
    /// case and Unicode composition).
    ///
    /// ```ignore
    /// self.check_custom_fields(&mut problems);
    /// ```
    fn check_custom_fields(&self, problems: &mut Vec<FieldProblem>) {
        if self.custom_fields.len() > MAX_CUSTOM_FIELDS {
            problems.push(FieldProblem::TooManyCustomFields);
        }
        for (i, field) in self.custom_fields.iter().enumerate() {
            problems.extend(check::custom_field_name(&field.name, &self.custom_fields[..i]).err());
            problems
                .extend(check::custom_field_value(&field.value, &self.custom_fields[..i]).err());
        }
    }
}
