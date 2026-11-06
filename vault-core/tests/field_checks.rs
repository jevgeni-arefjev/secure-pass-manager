//! The per-field checks (`session::check`): each field on its own, with the same
//! normalisation and rules as a save, so a front end can refuse an answer as it is
//! entered.

use vault_core::session::{CustomField, FieldProblem, FieldValue, HiddenValue, check};

#[test]
fn a_title_is_checked_after_trimming_and_nfc() {
    assert_eq!(check::title("  GitHub "), Ok(()));
    assert_eq!(check::title("   "), Err(FieldProblem::Title));
    assert_eq!(check::title("git\u{200b}hub"), Err(FieldProblem::Title));
    // 64 characters once NFC-normalised (each "e\u{301}" becomes one "é").
    assert_eq!(check::title(&"e\u{301}".repeat(64)), Ok(()));
    assert_eq!(check::title(&"x".repeat(65)), Err(FieldProblem::Title));
}

#[test]
fn optional_standard_fields_follow_their_rules() {
    assert_eq!(check::username(" alice "), Ok(()));
    assert_eq!(check::username("al\u{1b}ice"), Err(FieldProblem::Username));
    assert_eq!(check::url(" https://github.com "), Ok(()));
    assert_eq!(check::url("git\u{202e}hub.com"), Err(FieldProblem::Url));
    assert_eq!(
        check::url("ftp://example.com"),
        Err(FieldProblem::UnsupportedUrl)
    );
    assert_eq!(check::notes("line 1\n\tline 2"), Ok(()));
    assert_eq!(check::notes(&"n".repeat(4097)), Err(FieldProblem::Notes));
}

#[test]
fn a_password_is_checked_exactly_as_entered() {
    let password = |text: &str| check::password(&HiddenValue::new(text.to_owned()));
    assert_eq!(password("  spaces kept  "), Ok(()));
    assert_eq!(password("zero\u{200b}width"), Ok(()));
    assert_eq!(password(""), Err(FieldProblem::Password));
    assert_eq!(password("bell\u{7}"), Err(FieldProblem::Password));
    assert_eq!(password(&"x".repeat(1025)), Err(FieldProblem::Password));
}

#[test]
fn a_tag_is_checked_against_the_tags_before_it() {
    assert_eq!(check::tag("work", &[] as &[&str]), Ok(()));
    assert_eq!(check::tag(" ", &["dev"]), Err(FieldProblem::Tag(1)));
    assert_eq!(
        check::tag("CAFE\u{301}", &["dev", "caf\u{e9}"]),
        Err(FieldProblem::DuplicateTag(2))
    );
}

#[test]
fn a_custom_field_name_is_checked_against_earlier_and_standard_names() {
    let earlier = [CustomField::plain("Recovery code", "1234")];
    assert_eq!(check::custom_field_name("region", &earlier), Ok(()));
    assert_eq!(
        check::custom_field_name(" recovery CODE ", &earlier),
        Err(FieldProblem::DuplicateCustomFieldName(1))
    );
    assert_eq!(
        check::custom_field_name("URL", &[]),
        Err(FieldProblem::DuplicateCustomFieldName(0))
    );
    assert_eq!(
        check::custom_field_name("", &earlier),
        Err(FieldProblem::CustomFieldName(1))
    );
}

#[test]
fn an_empty_custom_field_value_is_refused_hidden_or_not() {
    let plain = |text: &str| FieldValue::Plain(text.to_owned().into());
    let hidden = |text: &str| FieldValue::Hidden(HiddenValue::new(text.to_owned()));
    assert_eq!(check::custom_field_value(&plain("eu-west"), &[]), Ok(()));
    assert_eq!(check::custom_field_value(&hidden(" 1234 "), &[]), Ok(()));
    let earlier = [
        CustomField::plain("region", "eu"),
        CustomField::plain("zone", "a"),
    ];
    for empty in [plain(""), plain("   "), hidden("")] {
        assert_eq!(
            check::custom_field_value(&empty, &earlier),
            Err(FieldProblem::CustomFieldValue(2))
        );
    }
    // A hidden value keeps its spaces, so spaces alone are a value.
    assert_eq!(check::custom_field_value(&hidden("  "), &[]), Ok(()));
}
