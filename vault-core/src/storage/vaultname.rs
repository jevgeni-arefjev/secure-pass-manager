//! The vaultname: the only user input that becomes part of a file path.

use std::fmt;

use super::StorageError;

/// Longest accepted vaultname, in characters.
const MAX_LEN: usize = 32;

/// A validated vaultname. It can only be built through [`Vaultname::parse`], so every
/// value is safe to use as a file name inside the vault directory (ADR-0001).
///
/// Security: input is lowercased, then must be 1–32 ASCII letters, digits, `-` or `_`,
/// starting with a letter or digit. Path separators, dots and Windows device names
/// (`con`, `nul`, `com1`, ...) can never get through, and two names differing only in
/// case are the same vault, so case-insensitive file systems can't make them collide.
///
/// ```
/// use vault_core::storage::Vaultname;
///
/// assert_eq!(Vaultname::parse("Alice")?.as_str(), "alice");
/// assert!(Vaultname::parse("../alice").is_err());
/// # Ok::<(), vault_core::storage::StorageError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Vaultname(String);

impl Vaultname {
    /// Validates `input` and returns it as a lowercase vaultname, or
    /// [`StorageError::InvalidVaultname`] if it breaks the rules on [`Vaultname`].
    ///
    /// ```
    /// # use vault_core::storage::{StorageError, Vaultname};
    /// assert_eq!(Vaultname::parse("bob-2_work")?.as_str(), "bob-2_work");
    /// assert_eq!(Vaultname::parse("con"), Err(StorageError::InvalidVaultname));
    /// # Ok::<(), StorageError>(())
    /// ```
    pub fn parse(input: &str) -> Result<Self, StorageError> {
        let name = input.to_ascii_lowercase();
        let valid = (1..=MAX_LEN).contains(&name.len())
            && name.starts_with(|c: char| c.is_ascii_alphanumeric())
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
            && !is_windows_device_name(&name);
        if valid {
            Ok(Self(name))
        } else {
            Err(StorageError::InvalidVaultname)
        }
    }

    /// The vaultname as a string, always lowercase.
    ///
    /// ```
    /// # use vault_core::storage::Vaultname;
    /// assert_eq!(Vaultname::parse("Alice")?.as_str(), "alice");
    /// # Ok::<(), vault_core::storage::StorageError>(())
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Vaultname {
    /// Writes the vaultname. Vaultnames aren't secret, so they may appear in messages
    /// and logs.
    ///
    /// ```
    /// # use vault_core::storage::Vaultname;
    /// assert_eq!(Vaultname::parse("alice")?.to_string(), "alice");
    /// # Ok::<(), vault_core::storage::StorageError>(())
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether a lowercase `name` is a reserved Windows device name, which can't be used
/// as a file name there even with an extension.
///
/// ```ignore
/// assert!(is_windows_device_name("com1"));
/// assert!(!is_windows_device_name("com10"));
/// ```
fn is_windows_device_name(name: &str) -> bool {
    match name.as_bytes() {
        b"con" | b"prn" | b"aux" | b"nul" => true,
        [b'c', b'o', b'm', digit] | [b'l', b'p', b't', digit] => digit.is_ascii_digit(),
        _ => false,
    }
}
