//! Each field's rules on its own, so a front end can refuse an answer as it is entered
//! (the vault shell re-asks it). A save runs these same checks on every field, plus the
//! whole-secret ones (how many tags and custom fields), so the two can't drift apart.
//!
//! Every check first puts the text into the form a save stores (non-hidden single-line
//! fields trimmed and NFC-normalised, notes NFC-normalised only, hidden fields as
//! entered), then applies the rules on [`FieldProblem`].
//!
//! Security: a problem names the rule, never the value, so it is safe to print.
//!
//! ```
//! use vault_core::session::{FieldProblem, check};
//! assert_eq!(check::title(" GitHub "), Ok(()));
//! assert_eq!(check::tag("WORK", &["work"]), Err(FieldProblem::DuplicateTag(1)));
//! ```

use super::text::{self, TextKind};
use super::{
    CustomField, FieldProblem, FieldValue, HiddenValue, MAX_FIELD_NAME, MAX_FIELD_VALUE,
    MAX_HIDDEN, MAX_NOTES, MAX_TAG, MAX_TITLE, MAX_URL, MAX_USERNAME, STANDARD_FIELD_NAMES, url,
};

/// Checks a title: 1-64 characters once trimmed, without unsafe characters.
///
/// ```
/// # use vault_core::session::{FieldProblem, check};
/// assert_eq!(check::title("GitHub"), Ok(()));
/// assert_eq!(check::title("  "), Err(FieldProblem::Title));
/// ```
///
/// # Errors
/// [`FieldProblem::Title`] if the title breaks a rule.
pub fn title(title: &str) -> Result<(), FieldProblem> {
    single_line(title, MAX_TITLE, FieldProblem::Title)
}

/// Checks a username: 1-256 characters once trimmed, without unsafe characters. A front
/// end leaves an empty optional username unset rather than checking it.
///
/// ```
/// # use vault_core::session::check;
/// assert_eq!(check::username("alice"), Ok(()));
/// ```
///
/// # Errors
/// [`FieldProblem::Username`] if the username breaks a rule.
pub fn username(username: &str) -> Result<(), FieldProblem> {
    single_line(username, MAX_USERNAME, FieldProblem::Username)
}

/// Checks a password: 1-1024 characters, without control characters. It is checked
/// exactly as entered, never trimmed or normalised.
///
/// ```
/// # use vault_core::session::{HiddenValue, check};
/// assert_eq!(check::password(&HiddenValue::new(" s3cret! ".into())), Ok(()));
/// ```
///
/// # Errors
/// [`FieldProblem::Password`] if the password breaks a rule.
pub fn password(password: &HiddenValue) -> Result<(), FieldProblem> {
    hidden(password, FieldProblem::Password)
}

/// Checks a URL: 1-2048 characters once trimmed, without unsafe characters, and an
/// `http`/`https` URL with a host or a bare host such as `github.com`.
///
/// ```
/// # use vault_core::session::{FieldProblem, check};
/// assert_eq!(check::url("github.com"), Ok(()));
/// assert_eq!(check::url("javascript:alert(1)"), Err(FieldProblem::UnsupportedUrl));
/// ```
///
/// # Errors
/// [`FieldProblem::Url`] for a broken text rule, else [`FieldProblem::UnsupportedUrl`]
/// for an address that isn't a supported URL.
pub fn url(url: &str) -> Result<(), FieldProblem> {
    text::in_stored_form(url, true, |url| {
        ok_if(
            text::is_valid(url, MAX_URL, TextKind::SingleLine),
            FieldProblem::Url,
        )?;
        ok_if(url::is_supported(url), FieldProblem::UnsupportedUrl)
    })
}

/// Checks notes: 1-4096 characters once NFC-normalised (not trimmed), without unsafe
/// characters other than newlines and tabs.
///
/// ```
/// # use vault_core::session::check;
/// assert_eq!(check::notes("2FA on\nbackup codes in safe"), Ok(()));
/// ```
///
/// # Errors
/// [`FieldProblem::Notes`] if the notes break a rule.
pub fn notes(notes: &str) -> Result<(), FieldProblem> {
    text::in_stored_form(notes, false, |notes| {
        ok_if(
            text::is_valid(notes, MAX_NOTES, TextKind::Notes),
            FieldProblem::Notes,
        )
    })
}

/// Checks a tag that follows the tags in `earlier`: 1-32 characters once trimmed,
/// without unsafe characters, and not repeating an earlier tag (ignoring case and
/// Unicode composition). The index in a problem is `earlier.len()`.
///
/// ```
/// # use vault_core::session::{FieldProblem, check};
/// assert_eq!(check::tag("work", &[] as &[&str]), Ok(()));
/// assert_eq!(check::tag(" Work", &["dev", "work"]), Err(FieldProblem::DuplicateTag(2)));
/// ```
///
/// # Errors
/// [`FieldProblem::Tag`] for a broken text rule, else [`FieldProblem::DuplicateTag`].
pub fn tag<S: AsRef<str>>(tag: &str, earlier: &[S]) -> Result<(), FieldProblem> {
    let index = earlier.len();
    single_line(tag, MAX_TAG, FieldProblem::Tag(index))?;
    ok_if(
        !earlier
            .iter()
            .any(|seen| text::same_folded(seen.as_ref(), tag)),
        FieldProblem::DuplicateTag(index),
    )
}

/// Checks the name of a custom field that follows the custom fields in `earlier`: 1-64
/// characters once trimmed, without unsafe characters, and neither a standard field
/// name nor an earlier custom field's name (ignoring case and Unicode composition).
/// The index in a problem is `earlier.len()`.
///
/// ```
/// # use vault_core::session::{CustomField, FieldProblem, check};
/// let earlier = [CustomField::plain("region", "eu")];
/// assert_eq!(check::custom_field_name("pin", &earlier), Ok(()));
/// assert_eq!(
///     check::custom_field_name("Password", &earlier),
///     Err(FieldProblem::DuplicateCustomFieldName(1))
/// );
/// ```
///
/// # Errors
/// [`FieldProblem::CustomFieldName`] for a broken text rule, else
/// [`FieldProblem::DuplicateCustomFieldName`].
pub fn custom_field_name(name: &str, earlier: &[CustomField]) -> Result<(), FieldProblem> {
    let index = earlier.len();
    single_line(name, MAX_FIELD_NAME, FieldProblem::CustomFieldName(index))?;
    let taken = STANDARD_FIELD_NAMES
        .iter()
        .any(|standard| text::same_folded(standard, name))
        || earlier
            .iter()
            .any(|seen| text::same_folded(seen.name(), name));
    ok_if(!taken, FieldProblem::DuplicateCustomFieldName(index))
}

/// Checks the value of a custom field that follows the custom fields in `earlier`. Not
/// hidden: 1-1024 characters once trimmed, without unsafe characters. Hidden: 1-1024
/// characters as entered, without control characters. Either way an empty value is
/// refused. The index in a problem is `earlier.len()`.
///
/// ```
/// # use vault_core::session::{FieldProblem, FieldValue, HiddenValue, check};
/// let empty = FieldValue::Hidden(HiddenValue::new(String::new()));
/// assert_eq!(check::custom_field_value(&empty, &[]), Err(FieldProblem::CustomFieldValue(0)));
/// ```
///
/// # Errors
/// [`FieldProblem::CustomFieldValue`] if the value breaks a rule.
pub fn custom_field_value(value: &FieldValue, earlier: &[CustomField]) -> Result<(), FieldProblem> {
    let problem = FieldProblem::CustomFieldValue(earlier.len());
    match value {
        FieldValue::Plain(text) => single_line(text, MAX_FIELD_VALUE, problem),
        FieldValue::Hidden(value) => hidden(value, problem),
    }
}

/// Checks a hidden value exactly as entered: 1-1024 characters, without control
/// characters.
///
/// ```ignore
/// hidden(password, FieldProblem::Password)?;
/// ```
fn hidden(value: &HiddenValue, problem: FieldProblem) -> Result<(), FieldProblem> {
    ok_if(
        text::is_valid(value.reveal(), MAX_HIDDEN, TextKind::Hidden),
        problem,
    )
}

/// Checks a non-hidden single-line field in its stored form (trimmed, NFC-normalised):
/// 1..=`max` characters, without unsafe characters.
///
/// ```ignore
/// single_line(" GitHub ", MAX_TITLE, FieldProblem::Title)?;
/// ```
fn single_line(text: &str, max: usize, problem: FieldProblem) -> Result<(), FieldProblem> {
    text::in_stored_form(text, true, |text| {
        ok_if(text::is_valid(text, max, TextKind::SingleLine), problem)
    })
}

/// `Ok` if `valid`, else `problem`.
///
/// ```ignore
/// ok_if(url::is_supported(url), FieldProblem::UnsupportedUrl)?;
/// ```
fn ok_if(valid: bool, problem: FieldProblem) -> Result<(), FieldProblem> {
    if valid { Ok(()) } else { Err(problem) }
}
