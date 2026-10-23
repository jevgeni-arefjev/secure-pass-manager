//! The minimum strength a new master password must have, checked when a vault is
//! created and when its master password is changed.
//!
//! No strength estimator (e.g. zxcvbn) is used: they copy the password into ordinary heap
//! strings (lowercased forms, match tokens) that are freed without zeroizing, which would
//! break the rule that no implicit copies of a secret are made.

use std::fmt;

use crate::crypto::MasterPassword;

/// Fewest characters (Unicode scalar values, after NFC) a new master password may have.
pub const MIN_MASTER_PASSWORD_CHARS: usize = 12;

/// Well-known passwords at least [`MIN_MASTER_PASSWORD_CHARS`] long, compared ignoring
/// ASCII case. Shorter ones are already refused by length.
const COMMON_PASSWORDS: &[&str] = &[
    "000000000000",
    "111111111111",
    "123123123123",
    "123321123321",
    "123456123456",
    "123456654321",
    "123456789012",
    "1234567890123",
    "12345678901234",
    "123456789123",
    "123456789abc",
    "1q2w3e4r5t6y",
    "1qaz2wsx3edc",
    "abc123456789",
    "abcdefghijkl",
    "administrator",
    "asdfghjkl123",
    "changeme1234",
    "iloveyou1234",
    "letmein12345",
    "passw0rd1234",
    "password1234",
    "password12345",
    "password123456",
    "password123!",
    "passwordpassword",
    "qazwsxedcrfv",
    "qwerty123456",
    "qwertyqwerty",
    "qwertyuiop12",
    "qwertyuiop123",
    "qwertyuiopasdfgh",
    "welcome12345",
    "zaq12wsxcde3",
];

/// Why a new master password was refused. Messages state the rule, never the password.
///
/// ```
/// use vault_core::session::WeakMasterPassword;
/// assert_eq!(
///     WeakMasterPassword::TooShort.to_string(),
///     "master password must be at least 12 characters"
/// );
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WeakMasterPassword {
    /// Fewer than [`MIN_MASTER_PASSWORD_CHARS`] characters.
    TooShort,
    /// One character repeated, or on the built-in list of common passwords.
    TooCommon,
}

impl fmt::Display for WeakMasterPassword {
    /// Writes the rule that was broken.
    ///
    /// ```
    /// # use vault_core::session::WeakMasterPassword;
    /// assert_eq!(WeakMasterPassword::TooCommon.to_string(), "master password is too common");
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => write!(
                f,
                "master password must be at least {MIN_MASTER_PASSWORD_CHARS} characters"
            ),
            Self::TooCommon => f.write_str("master password is too common"),
        }
    }
}

/// Checks that `password` is strong enough to protect a new vault.
///
/// Security: works on the locked bytes directly; no copy of the password (not even a
/// lowercased one) is made.
///
/// ```ignore
/// check(&MasterPassword::new("hunter2".into())) == Err(WeakMasterPassword::TooShort)
/// ```
pub(super) fn check(password: &MasterPassword) -> Result<(), WeakMasterPassword> {
    let text = std::str::from_utf8(password.as_bytes()).expect("built from a String");
    if text.chars().count() < MIN_MASTER_PASSWORD_CHARS {
        return Err(WeakMasterPassword::TooShort);
    }
    let mut chars = text.chars();
    let first = chars.next();
    let one_repeated_char = chars.all(|c| Some(c) == first);
    let listed = COMMON_PASSWORDS
        .iter()
        .any(|common| common.as_bytes().eq_ignore_ascii_case(text.as_bytes()));
    if one_repeated_char || listed {
        return Err(WeakMasterPassword::TooCommon);
    }
    Ok(())
}
