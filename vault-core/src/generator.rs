//! Password generator: random text passwords for new secrets, shared by the CLI and,
//! later, the web front end.
//!
//! Security:
//! - Randomness comes only from the OS CSPRNG ([`getrandom`]), drawn without modulo bias.
//! - Each password is built in a zeroizing buffer and moved into a [`HiddenValue`]; the
//!   random bytes and any rejected draw are wiped too.
//! - Passwords missing a character class are redrawn whole, never patched, so every
//!   password with all classes is equally likely.
//!
//! ```
//! use vault_core::generator::{self, DEFAULT_PASSWORD_LENGTH};
//!
//! let password = generator::generate_password(DEFAULT_PASSWORD_LENGTH)?;
//! assert_eq!(password.reveal().len(), DEFAULT_PASSWORD_LENGTH);
//! # Ok::<(), vault_core::generator::GeneratorError>(())
//! ```

use std::fmt;

use zeroize::{Zeroize, Zeroizing};

use crate::session::HiddenValue;

/// Length used when the person doesn't ask for one.
pub const DEFAULT_PASSWORD_LENGTH: usize = 24;

/// Shortest password the generator makes (about 79 bits of entropy).
pub const MIN_PASSWORD_LENGTH: usize = 12;

/// Longest password the generator makes.
pub const MAX_PASSWORD_LENGTH: usize = 128;

/// Visible ASCII, `!` to `~`: letters, digits and symbols, without space.
const ALPHABET: [u8; 94] = {
    let mut alphabet = [0; 94];
    let mut i = 0;
    while i < alphabet.len() {
        alphabet[i] = b'!' + i as u8;
        i += 1;
    }
    alphabet
};

/// Random bytes at or above this are dropped, so `byte % 94` stays uniform.
const REJECT_FROM: u8 = (256 / ALPHABET.len() * ALPHABET.len()) as u8;

/// Why no password was generated. Messages are fixed strings.
///
/// ```
/// use vault_core::generator::GeneratorError;
/// assert_eq!(GeneratorError::Randomness.to_string(), "the OS random number generator failed");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GeneratorError {
    /// Length outside [`MIN_PASSWORD_LENGTH`]..=[`MAX_PASSWORD_LENGTH`].
    InvalidLength,
    /// The OS random number generator failed.
    Randomness,
}

impl fmt::Display for GeneratorError {
    /// Writes the fixed message for this error.
    ///
    /// ```
    /// # use vault_core::generator::GeneratorError;
    /// assert_eq!(
    ///     GeneratorError::InvalidLength.to_string(),
    ///     "password length must be 12-128 characters"
    /// );
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => write!(
                f,
                "password length must be {MIN_PASSWORD_LENGTH}-{MAX_PASSWORD_LENGTH} characters"
            ),
            Self::Randomness => f.write_str("the OS random number generator failed"),
        }
    }
}

impl std::error::Error for GeneratorError {}

/// A random password of `length` visible ASCII characters with at least one lowercase
/// letter, uppercase letter, digit and symbol.
///
/// Security: the result is a [`HiddenValue`]; reveal it only to show or copy it on the
/// person's explicit request.
///
/// ```
/// use vault_core::generator::{self, GeneratorError};
///
/// let password = generator::generate_password(16)?;
/// assert!(password.reveal().chars().all(|c| c.is_ascii_graphic()));
/// assert_eq!(generator::generate_password(4).err(), Some(GeneratorError::InvalidLength));
/// # Ok::<(), GeneratorError>(())
/// ```
pub fn generate_password(length: usize) -> Result<HiddenValue, GeneratorError> {
    if !(MIN_PASSWORD_LENGTH..=MAX_PASSWORD_LENGTH).contains(&length) {
        return Err(GeneratorError::InvalidLength);
    }
    let mut password = Zeroizing::new(Vec::with_capacity(length));
    loop {
        fill_uniform(&mut password, length)?;
        if has_every_class(&password) {
            break;
        }
        password.zeroize();
    }
    let text = String::from_utf8(std::mem::take(&mut *password)).expect("alphabet is ASCII");
    Ok(HiddenValue::new(text))
}

/// Appends `length` characters drawn uniformly from [`ALPHABET`] to `out`, which must
/// have room for them (so it never reallocates and leaves a copy behind).
///
/// ```ignore
/// fill_uniform(&mut password, 24)?;
/// ```
fn fill_uniform(out: &mut Vec<u8>, length: usize) -> Result<(), GeneratorError> {
    let mut random = Zeroizing::new([0u8; 64]);
    while out.len() < length {
        getrandom::fill(&mut *random).map_err(|_| GeneratorError::Randomness)?;
        let accepted = random.iter().filter(|&&byte| byte < REJECT_FROM);
        for &byte in accepted.take(length - out.len()) {
            out.push(ALPHABET[usize::from(byte) % ALPHABET.len()]);
        }
    }
    Ok(())
}

/// Whether `password` has a lowercase letter, an uppercase letter, a digit and a symbol.
///
/// ```ignore
/// assert!(has_every_class(b"aB3!"));
/// ```
fn has_every_class(password: &[u8]) -> bool {
    let has = |class: fn(&u8) -> bool| password.iter().any(class);
    has(u8::is_ascii_lowercase)
        && has(u8::is_ascii_uppercase)
        && has(u8::is_ascii_digit)
        && has(u8::is_ascii_punctuation)
}
