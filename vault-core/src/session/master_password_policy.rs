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

/// Most characters (Unicode scalar values, after NFC) a new master password may have:
/// the most the vault shell's hidden prompt takes, so a vault created anywhere can be
/// unlocked from the CLI.
pub const MAX_MASTER_PASSWORD_CHARS: usize = 1024;

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
    /// More than [`MAX_MASTER_PASSWORD_CHARS`] characters.
    TooLong,
    /// Holds a control character (such as a newline, tab or escape), which a hidden
    /// prompt can't take.
    ControlCharacter,
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
            Self::TooLong => write!(
                f,
                "master password must be at most {MAX_MASTER_PASSWORD_CHARS} characters"
            ),
            Self::ControlCharacter => {
                f.write_str("master password must not contain control characters")
            }
            Self::TooCommon => f.write_str("master password is too common"),
        }
    }
}

/// Checks that `password` is strong enough to protect a new vault and can be typed at
/// any prompt: 12-1024 characters after NFC, no control characters, not too common.
/// Unlock never runs it, so a vault whose master password predates a rule still opens
/// and can be given a new one. Exported as
/// `session::check_master_password` so front ends can reject a weak password before
/// asking the user to repeat it; `Session::create` and `change_master_password` still
/// call it themselves.
///
/// Security: works on the locked bytes directly; no copy of the password (not even a
/// lowercased one) is made.
///
/// ```
/// use vault_core::crypto::MasterPassword;
/// use vault_core::session::{check_master_password, WeakMasterPassword};
/// assert_eq!(
///     check_master_password(&MasterPassword::new("hunter2".into())),
///     Err(WeakMasterPassword::TooShort)
/// );
/// assert!(check_master_password(&MasterPassword::new("correct horse battery".into())).is_ok());
/// ```
pub fn check(password: &MasterPassword) -> Result<(), WeakMasterPassword> {
    let text = std::str::from_utf8(password.as_bytes()).expect("built from a String");
    let chars = text.chars().count();
    if chars < MIN_MASTER_PASSWORD_CHARS {
        return Err(WeakMasterPassword::TooShort);
    }
    if chars > MAX_MASTER_PASSWORD_CHARS {
        return Err(WeakMasterPassword::TooLong);
    }
    if text.chars().any(char::is_control) {
        return Err(WeakMasterPassword::ControlCharacter);
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
