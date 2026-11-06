//! Why a secret was refused: every broken field rule at once, each naming its field
//! (and, for tags and custom fields, which one and which part) with a fixed message.
//!
//! Security: nothing here holds or prints a value; messages state the rule only.

use std::fmt;

use super::{
    MAX_CUSTOM_FIELDS, MAX_FIELD_NAME, MAX_FIELD_VALUE, MAX_HIDDEN, MAX_NOTES, MAX_TAG, MAX_TAGS,
    MAX_TITLE, MAX_URL, MAX_USERNAME,
};

/// A field of a secret, as named in a [`FieldProblem`].
///
/// ```
/// use vault_core::session::{FieldProblem, SecretField};
/// assert_eq!(FieldProblem::DuplicateTag(1).field(), SecretField::Tags);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretField {
    /// The title.
    Title,
    /// The username.
    Username,
    /// The password.
    Password,
    /// The URL.
    Url,
    /// The notes.
    Notes,
    /// The tags, as a whole or one of them.
    Tags,
    /// The custom fields, as a whole or one of them.
    CustomFields,
}

/// The part of a custom field a [`FieldProblem`] is about.
///
/// ```
/// use vault_core::session::{CustomFieldPart, FieldProblem};
/// assert_eq!(FieldProblem::CustomFieldValue(0).part(), Some(CustomFieldPart::Value));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CustomFieldPart {
    /// The custom field's name.
    Name,
    /// The custom field's value.
    Value,
}

/// One broken field rule. Indexes are 0-based positions among the secret's tags or
/// custom fields. The message ([`fmt::Display`]) states the rule, never the value.
///
/// ```
/// use vault_core::session::FieldProblem;
/// assert_eq!(
///     FieldProblem::Title.to_string(),
///     "title must be 1-64 characters, without control or formatting characters"
/// );
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldProblem {
    /// Title empty after trimming, over 64 characters, or with an unsafe character
    /// (control, format or line/paragraph separator; see [`is_unsafe_char`]).
    ///
    /// [`is_unsafe_char`]: super::is_unsafe_char
    Title,
    /// Username empty after trimming, over 256 characters, or with an unsafe character.
    Username,
    /// Password empty, over 1024 characters, or with control characters.
    Password,
    /// URL empty after trimming, over 2048 characters, or with an unsafe character.
    Url,
    /// URL not an `http`/`https` URL with a host, nor a bare host such as `github.com`.
    UnsupportedUrl,
    /// Notes empty, over 4096 characters, or with an unsafe character other than
    /// newlines and tabs.
    Notes,
    /// More than 32 tags.
    TooManyTags,
    /// The tag at this index is empty after trimming, over 32 characters, or has an
    /// unsafe character.
    Tag(usize),
    /// The tag at this index repeats an earlier one, ignoring case and Unicode
    /// composition.
    DuplicateTag(usize),
    /// More than 32 custom fields.
    TooManyCustomFields,
    /// The custom field name at this index is empty after trimming, over 64
    /// characters, or has an unsafe character.
    CustomFieldName(usize),
    /// The custom field value at this index is empty, over 1024 characters, or has an
    /// unsafe character (if hidden: a control character).
    CustomFieldValue(usize),
    /// The custom field name at this index repeats an earlier one or a standard field
    /// name, ignoring case and Unicode composition.
    DuplicateCustomFieldName(usize),
}

impl FieldProblem {
    /// The field this problem is about.
    ///
    /// ```
    /// # use vault_core::session::{FieldProblem, SecretField};
    /// assert_eq!(FieldProblem::CustomFieldName(2).field(), SecretField::CustomFields);
    /// ```
    #[must_use]
    pub fn field(&self) -> SecretField {
        match self {
            Self::Title => SecretField::Title,
            Self::Username => SecretField::Username,
            Self::Password => SecretField::Password,
            Self::Url | Self::UnsupportedUrl => SecretField::Url,
            Self::Notes => SecretField::Notes,
            Self::TooManyTags | Self::Tag(_) | Self::DuplicateTag(_) => SecretField::Tags,
            Self::TooManyCustomFields
            | Self::CustomFieldName(_)
            | Self::CustomFieldValue(_)
            | Self::DuplicateCustomFieldName(_) => SecretField::CustomFields,
        }
    }

    /// The 0-based index of the tag or custom field at fault; `None` for a standard
    /// field or a problem with the whole list (too many).
    ///
    /// ```
    /// # use vault_core::session::FieldProblem;
    /// assert_eq!(FieldProblem::Tag(3).index(), Some(3));
    /// assert_eq!(FieldProblem::TooManyTags.index(), None);
    /// ```
    #[must_use]
    pub fn index(&self) -> Option<usize> {
        match *self {
            Self::Tag(i)
            | Self::DuplicateTag(i)
            | Self::CustomFieldName(i)
            | Self::CustomFieldValue(i)
            | Self::DuplicateCustomFieldName(i) => Some(i),
            _ => None,
        }
    }

    /// For a custom field problem, whether its name or its value is at fault.
    ///
    /// ```
    /// # use vault_core::session::{CustomFieldPart, FieldProblem};
    /// assert_eq!(FieldProblem::DuplicateCustomFieldName(0).part(), Some(CustomFieldPart::Name));
    /// assert_eq!(FieldProblem::Title.part(), None);
    /// ```
    #[must_use]
    pub fn part(&self) -> Option<CustomFieldPart> {
        match self {
            Self::CustomFieldName(_) | Self::DuplicateCustomFieldName(_) => {
                Some(CustomFieldPart::Name)
            }
            Self::CustomFieldValue(_) => Some(CustomFieldPart::Value),
            _ => None,
        }
    }
}

impl fmt::Display for FieldProblem {
    /// Writes the rule that was broken.
    ///
    /// ```
    /// # use vault_core::session::FieldProblem;
    /// assert_eq!(FieldProblem::TooManyTags.to_string(), "a secret can have at most 32 tags");
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rule = |field: &str, max: usize| {
            format!("{field} must be 1-{max} characters, without control or formatting characters")
        };
        let message = match self {
            Self::Title => rule("title", MAX_TITLE),
            Self::Username => rule("username", MAX_USERNAME),
            Self::Password => {
                format!("password must be 1-{MAX_HIDDEN} characters, without control characters")
            }
            Self::Url => rule("URL", MAX_URL),
            Self::UnsupportedUrl => "URL must be an http:// or https:// address with a host, \
                or a bare host such as github.com; keep other addresses in notes or a custom field"
                .to_owned(),
            Self::Notes => format!(
                "notes must be 1-{MAX_NOTES} characters, without control or formatting characters other than newlines and tabs"
            ),
            Self::TooManyTags => format!("a secret can have at most {MAX_TAGS} tags"),
            Self::Tag(_) => rule("each tag", MAX_TAG),
            Self::DuplicateTag(_) => "tags must be unique, ignoring case".to_owned(),
            Self::TooManyCustomFields => {
                format!("a secret can have at most {MAX_CUSTOM_FIELDS} custom fields")
            }
            Self::CustomFieldName(_) => rule("custom field names", MAX_FIELD_NAME),
            Self::CustomFieldValue(_) => format!(
                "custom field values must be 1-{MAX_FIELD_VALUE} characters, without control or formatting characters (hidden: 1-{MAX_HIDDEN}, without control characters)"
            ),
            Self::DuplicateCustomFieldName(_) => {
                "custom field names must be unique and differ from the standard fields".to_owned()
            }
        };
        f.write_str(&message)
    }
}

/// Why a secret was refused: every [`FieldProblem`] found, in field order (title,
/// username, password, URL, notes, tags, custom fields). Never empty.
///
/// ```
/// # use vault_core::session::{FieldProblem, InvalidSecret};
/// fn report(invalid: &InvalidSecret) {
///     for problem in invalid.problems() {
///         eprintln!("{:?} {:?}: {problem}", problem.field(), problem.index());
///     }
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidSecret {
    /// Every problem found, in field order; never empty.
    problems: Vec<FieldProblem>,
}

impl InvalidSecret {
    /// `Ok` if `problems` is empty, else the error carrying them all.
    ///
    /// ```ignore
    /// InvalidSecret::from_problems(problems)?;
    /// ```
    pub(in crate::session) fn from_problems(problems: Vec<FieldProblem>) -> Result<(), Self> {
        if problems.is_empty() {
            Ok(())
        } else {
            Err(Self { problems })
        }
    }

    /// Every problem found, in field order.
    ///
    /// ```ignore
    /// let fields: Vec<_> = invalid.problems().iter().map(FieldProblem::field).collect();
    /// ```
    #[must_use]
    pub fn problems(&self) -> &[FieldProblem] {
        &self.problems
    }
}

impl fmt::Display for InvalidSecret {
    /// Writes every problem's rule, separated by `; `.
    ///
    /// ```ignore
    /// // "title must be 1-64 characters, ...; tags must be unique, ignoring case"
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, problem) in self.problems.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            problem.fmt(f)?;
        }
        Ok(())
    }
}

impl std::error::Error for InvalidSecret {}
