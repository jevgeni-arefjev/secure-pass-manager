//! The character rules for secret fields (ADR-0013): which characters each kind of
//! field refuses, how non-hidden fields are trimmed and NFC-normalised, and how titles,
//! tags and custom field names are compared.
//!
//! Security: non-hidden fields refuse every control character, the whole Unicode format
//! category (Cf: zero-width characters, bidirectional controls, tag characters, ...)
//! and the line and paragraph separators, so nothing invisible can disguise a title or
//! drive a terminal or page. Hidden fields refuse only control characters and are never
//! changed: the service a password belongs to compares it byte for byte.

use unicode_general_category::{GeneralCategory, get_general_category};
use unicode_normalization::{UnicodeNormalization, is_nfc};
use zeroize::Zeroizing;

/// The rules a field's text follows.
///
/// ```ignore
/// assert!(is_valid("work", MAX_TAG, TextKind::SingleLine));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TextKind {
    /// A non-hidden single-line field: title, username, URL, tag, custom field name or
    /// non-hidden custom field value. Trimmed and NFC-normalised on save.
    SingleLine,
    /// Notes: NFC-normalised but not trimmed; keeps newlines and tabs.
    Notes,
    /// A hidden field: the password or a hidden custom field value. Stored as entered.
    Hidden,
}

/// Whether `c` is refused in a non-hidden field, and so escaped by every front end that
/// shows stored text: control characters, the Unicode format category (Cf) and the
/// line and paragraph separators (U+2028, U+2029). With `multiline` (notes), newline
/// and tab are allowed.
///
/// Security: front ends must escape exactly these characters when showing a stored
/// field, so a vault written by another build still can't drive the display. The
/// shared fixture `fixtures/unsafe-characters.json` keeps the core and both front ends
/// in step.
///
/// ```
/// use vault_core::session::is_unsafe_char;
/// assert!(is_unsafe_char('\u{1b}', false)); // escape
/// assert!(is_unsafe_char('\u{202e}', false)); // right-to-left override
/// assert!(is_unsafe_char('\u{ad}', false)); // soft hyphen
/// assert!(is_unsafe_char('\n', false));
/// assert!(!is_unsafe_char('\n', true));
/// assert!(!is_unsafe_char('é', false));
/// ```
#[must_use]
pub fn is_unsafe_char(c: char, multiline: bool) -> bool {
    if multiline && matches!(c, '\n' | '\t') {
        return false;
    }
    matches!(
        get_general_category(c),
        GeneralCategory::Control
            | GeneralCategory::Format
            | GeneralCategory::LineSeparator
            | GeneralCategory::ParagraphSeparator
    )
}

/// Whether `text` is 1..=`max` characters and holds no character its kind refuses.
/// Length is counted in characters (Unicode scalar values), not bytes.
///
/// ```ignore
/// assert!(is_valid("github", 64, TextKind::SingleLine));
/// assert!(!is_valid("git\u{200b}hub", 64, TextKind::SingleLine));
/// assert!(is_valid("git\u{200b}hub", 1024, TextKind::Hidden));
/// ```
pub(super) fn is_valid(text: &str, max: usize, kind: TextKind) -> bool {
    let allowed = |c: char| match kind {
        TextKind::SingleLine => !is_unsafe_char(c, false),
        TextKind::Notes => !is_unsafe_char(c, true),
        TextKind::Hidden => !c.is_control(),
    };
    (1..=max).contains(&text.chars().count()) && text.chars().all(allowed)
}

/// Puts a single-line non-hidden field into its stored form, in place: trimmed and
/// NFC-normalised. Never for hidden fields, which are stored as entered.
///
/// ```ignore
/// let mut title = Zeroizing::new(String::from("  Cafe\u{301} "));
/// normalize_single_line(&mut title);
/// assert_eq!(title.as_str(), "Caf\u{e9}");
/// ```
pub(super) fn normalize_single_line(field: &mut Zeroizing<String>) {
    normalize(field, true);
}

/// Puts notes into their stored form, in place: NFC-normalised, not trimmed.
///
/// ```ignore
/// let mut notes = Zeroizing::new(String::from(" cafe\u{301}\n"));
/// normalize_notes(&mut notes);
/// assert_eq!(notes.as_str(), " caf\u{e9}\n");
/// ```
pub(super) fn normalize_notes(field: &mut Zeroizing<String>) {
    normalize(field, false);
}

/// NFC-normalises `field` in place, trimming it first if `trim`.
///
/// Security: a changed field is rebuilt in a buffer sized exactly up front (one pass
/// measures, a second writes), so no unzeroized copy is left by a reallocation; the
/// old text is zeroized when it is dropped. An unchanged field isn't copied at all.
///
/// ```ignore
/// normalize(&mut tag, true);
/// ```
fn normalize(field: &mut Zeroizing<String>, trim: bool) {
    let text = if trim { field.trim() } else { field.as_str() };
    if text.len() == field.len() && is_nfc(text) {
        return;
    }
    *field = nfc_copy(text);
}

/// Runs `f` on `text` in the form a save stores it (trimmed if `trim`, then
/// NFC-normalised), without changing `text`. Text already in that form is borrowed, not
/// copied.
///
/// Security: a copy, when one is needed, is zeroized once `f` returns.
///
/// ```ignore
/// let valid = in_stored_form(" Cafe\u{301}", true, |title| is_valid(title, 64, TextKind::SingleLine));
/// ```
pub(super) fn in_stored_form<R>(text: &str, trim: bool, f: impl FnOnce(&str) -> R) -> R {
    let text = if trim { text.trim() } else { text };
    if is_nfc(text) {
        return f(text);
    }
    f(&nfc_copy(text))
}

/// `text` NFC-normalised into a new zeroizing string.
///
/// Security: the buffer is sized exactly up front (one pass measures, a second writes),
/// so no unzeroized copy is left behind by a reallocation.
///
/// ```ignore
/// assert_eq!(nfc_copy("cafe\u{301}").as_str(), "caf\u{e9}");
/// ```
fn nfc_copy(text: &str) -> Zeroizing<String> {
    let len = text.nfc().map(char::len_utf8).sum();
    let mut out = Zeroizing::new(String::with_capacity(len));
    out.extend(text.nfc());
    out
}

/// `text` as compared for lookups and duplicates: trimmed, NFC-normalised and lowercased,
/// lazily, without allocating a copy.
///
/// ```ignore
/// assert!(folded(" CAFE\u{301}").eq(folded("caf\u{e9}")));
/// ```
pub(super) fn folded(text: &str) -> impl Iterator<Item = char> + '_ {
    text.trim().nfc().flat_map(char::to_lowercase)
}

/// Whether `a` and `b` are the same title, tag or custom field name: equal once
/// trimmed, NFC-normalised and lowercased.
///
/// ```ignore
/// assert!(same_folded("Caf\u{e9}", " cafe\u{301}"));
/// ```
pub(super) fn same_folded(a: &str, b: &str) -> bool {
    folded(a).eq(folded(b))
}
