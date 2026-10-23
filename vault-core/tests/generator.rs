//! Behaviour of the password generator, tested only through its public API.

use vault_core::generator::{
    self, DEFAULT_PASSWORD_LENGTH, GeneratorError, MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH,
};

/// Every length in the allowed range gives a password of exactly that many characters.
#[test]
fn generated_password_has_the_requested_length() {
    for length in [
        MIN_PASSWORD_LENGTH,
        DEFAULT_PASSWORD_LENGTH,
        MAX_PASSWORD_LENGTH,
    ] {
        let password = generator::generate_password(length).unwrap();
        assert_eq!(password.reveal().chars().count(), length);
    }
}

/// Only visible ASCII is used: no space, no control characters, nothing outside ASCII.
#[test]
fn generated_password_uses_only_visible_ascii() {
    for _ in 0..200 {
        let password = generator::generate_password(MIN_PASSWORD_LENGTH).unwrap();
        assert!(password.reveal().chars().all(|c| c.is_ascii_graphic()));
    }
}

/// Every password, even at the minimum length, has a lowercase and an uppercase letter,
/// a digit and a symbol, so it passes services' composition rules.
#[test]
fn generated_password_has_every_character_class() {
    for _ in 0..500 {
        let password = generator::generate_password(MIN_PASSWORD_LENGTH).unwrap();
        let text = password.reveal();
        assert!(text.chars().any(|c| c.is_ascii_lowercase()), "no lowercase");
        assert!(text.chars().any(|c| c.is_ascii_uppercase()), "no uppercase");
        assert!(text.chars().any(|c| c.is_ascii_digit()), "no digit");
        assert!(text.chars().any(|c| c.is_ascii_punctuation()), "no symbol");
    }
}

/// Over many draws every one of the 94 visible ASCII characters shows up, so no class
/// or character is left out of the alphabet.
#[test]
fn generator_draws_from_the_whole_alphabet() {
    let mut seen = std::collections::HashSet::new();
    for _ in 0..200 {
        let password = generator::generate_password(MAX_PASSWORD_LENGTH).unwrap();
        seen.extend(password.reveal().chars());
    }
    assert_eq!(seen.len(), 94);
}

/// Two passwords in a row are different (a stuck or seeded RNG would repeat).
#[test]
fn generated_passwords_differ() {
    let first = generator::generate_password(DEFAULT_PASSWORD_LENGTH).unwrap();
    let second = generator::generate_password(DEFAULT_PASSWORD_LENGTH).unwrap();
    assert_ne!(first.reveal(), second.reveal());
}

/// Lengths outside the allowed range are refused, not clamped.
#[test]
fn length_outside_the_allowed_range_is_refused() {
    for length in [0, MIN_PASSWORD_LENGTH - 1, MAX_PASSWORD_LENGTH + 1] {
        assert_eq!(
            generator::generate_password(length).err(),
            Some(GeneratorError::InvalidLength)
        );
    }
}

/// The error message states the allowed range.
#[test]
fn invalid_length_message_states_the_range() {
    assert_eq!(
        GeneratorError::InvalidLength.to_string(),
        format!("password length must be {MIN_PASSWORD_LENGTH}-{MAX_PASSWORD_LENGTH} characters")
    );
}
