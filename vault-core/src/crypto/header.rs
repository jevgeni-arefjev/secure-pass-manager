//! The vault header: plaintext metadata stored next to the encrypted body, and its
//! fixed byte encoding.
//!
//! Layout (big-endian, fixed 126 bytes):
//!
//! | Field          | Size | Description |
//! | -------------- | ---- | ----------- |
//! | magic `SPMV`   | 4    | Identifies file as vault file |
//! | format version | 2    | Determines KDF and its params |
//! | salt           | 16   | Random value for KDF |
//! | wrap nonce     | 24   |  |
//! | wrapped key    | 48   | Encrypted vault key |
//! | revision       | 8    | Counter of changes to the vault |
//! | body nonce     | 24   |  |
//!
//! Magic, format version and salt are the associated data of the key wrap; the whole
//! encoding is the associated data of the body. The format version alone fixes the KDF
//! and its params (ADR-0005); the vaultname is only the file name (ADR-0004). The
//! encoding must never change for an existing format version, or existing vaults stop
//! decrypting.

use super::CryptoError;
use super::kdf::{KEY_LEN, KdfParams};

const MAGIC: &[u8; 4] = b"SPMV";
/// Magic, format version, salt.
const WRAP_AAD_LEN: usize = 4 + 2 + SALT_LEN;

pub(crate) const SALT_LEN: usize = 16;
pub(crate) const NONCE_LEN: usize = 24;
pub(crate) const TAG_LEN: usize = 16;
pub(crate) const WRAPPED_KEY_LEN: usize = KEY_LEN + TAG_LEN;

/// The top bit of a format version marks a test format: the same layout as the
/// production version in the low bits, with a cheap KDF (ADR-0005).
#[cfg(feature = "insecure-test-kdf")]
const TEST_FORMAT_BIT: u16 = 0x8000;

/// A vault format the app can read. The version written to the header determines
/// the KDF and its params, so no cost parameter is ever read from untrusted bytes.
///
/// Security: test formats exist only with the `insecure-test-kdf` feature, so a
/// release build can neither write nor open them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Format {
    /// Argon2id, 256 MiB, t=3, p=1. Written for every new vault.
    V1,
    /// Version 1's layout with [`KdfParams::INSECURE_TEST`]. Tests only.
    #[cfg(feature = "insecure-test-kdf")]
    V1InsecureTest,
}

impl Format {
    /// The format new vaults are created in.
    pub(crate) const CURRENT: Self = Self::V1;

    /// The version number written to the header.
    ///
    /// ```ignore
    /// assert_eq!(Format::V1.version(), 0x0001);
    /// ```
    fn version(self) -> u16 {
        match self {
            Self::V1 => 0x0001,
            #[cfg(feature = "insecure-test-kdf")]
            Self::V1InsecureTest => 0x0001 | TEST_FORMAT_BIT,
        }
    }

    /// The format for a version number read from a header; `None` if unknown.
    ///
    /// ```ignore
    /// assert_eq!(Format::from_version(0x0001), Some(Format::V1));
    /// ```
    fn from_version(version: u16) -> Option<Self> {
        [
            Self::V1,
            #[cfg(feature = "insecure-test-kdf")]
            Self::V1InsecureTest,
        ]
        .into_iter()
        .find(|format| format.version() == version)
    }

    /// The Argon2id params this format derives the KEK with.
    ///
    /// ```ignore
    /// let kek = derive_kek(&password, header.format.kdf_params(), &header.salt)?;
    /// ```
    pub(crate) fn kdf_params(self) -> KdfParams {
        match self {
            Self::V1 => KdfParams::V1,
            #[cfg(feature = "insecure-test-kdf")]
            Self::V1InsecureTest => KdfParams::INSECURE_TEST,
        }
    }
}

/// The plaintext part of a vault file. Holds no secrets: the vault key in it is
/// wrapped (encrypted) under the KEK.
///
/// Security: every field is authenticated, and [`Header::decode`] rejects unknown
/// formats before any key derivation runs.
///
/// ```
/// # use vault_core::crypto::{self, MasterPassword, Plaintext, Header};
/// # let password = MasterPassword::new("hunter2".into());
/// # let (_, sealed) = crypto::create_insecure_for_tests(&password, &Plaintext::new(vec![]))?;
/// let bytes = sealed.header.encode();
/// assert_eq!(Header::decode(&bytes)?, sealed.header);
/// # Ok::<(), crypto::CryptoError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub(crate) format: Format,
    pub(crate) salt: [u8; SALT_LEN],
    pub(crate) wrap_nonce: [u8; NONCE_LEN],
    pub(crate) wrapped_key: [u8; WRAPPED_KEY_LEN],
    pub(crate) revision: u64,
    pub(crate) body_nonce: [u8; NONCE_LEN],
}

impl Header {
    /// Length of every encoded header, in bytes. Storage reads exactly this much before
    /// the body (ADR-0011).
    ///
    /// ```
    /// # use vault_core::crypto::{self, MasterPassword, Plaintext, Header};
    /// # let password = MasterPassword::new("hunter2".into());
    /// # let (_, sealed) = crypto::create_insecure_for_tests(&password, &Plaintext::new(vec![]))?;
    /// assert_eq!(sealed.header.encode().len(), Header::LEN);
    /// # Ok::<(), crypto::CryptoError>(())
    /// ```
    pub const LEN: usize = WRAP_AAD_LEN + NONCE_LEN + WRAPPED_KEY_LEN + 8 + NONCE_LEN;

    /// The save counter: 0 at creation, +1 on every save. Orders backups and writes;
    /// it is not rollback protection.
    ///
    /// ```
    /// # use vault_core::crypto::{self, MasterPassword, Plaintext};
    /// # let password = MasterPassword::new("hunter2".into());
    /// # let (_, sealed) = crypto::create_insecure_for_tests(&password, &Plaintext::new(vec![]))?;
    /// assert_eq!(sealed.header.revision(), 0);
    /// # Ok::<(), crypto::CryptoError>(())
    /// ```
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Encodes the header in the fixed layout described in the module docs.
    ///
    /// ```
    /// # use vault_core::crypto::{self, MasterPassword, Plaintext};
    /// # let password = MasterPassword::new("hunter2".into());
    /// # let (_, sealed) = crypto::create_insecure_for_tests(&password, &Plaintext::new(vec![]))?;
    /// assert!(sealed.header.encode().starts_with(b"SPMV"));
    /// # Ok::<(), crypto::CryptoError>(())
    /// ```
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.wrap_aad();
        out.extend_from_slice(&self.wrap_nonce);
        out.extend_from_slice(&self.wrapped_key);
        out.extend_from_slice(&self.revision.to_be_bytes());
        out.extend_from_slice(&self.body_nonce);
        out
    }

    /// Parses an encoded header, strictly: exact length, known magic and a format
    /// version this build supports.
    ///
    /// Security: this is the parser for attacker-controlled bytes. Any mismatch gives
    /// [`CryptoError::UnsupportedFormat`], with no detail about what was wrong.
    ///
    /// ```
    /// # use vault_core::crypto::{Header, CryptoError};
    /// assert_eq!(Header::decode(b"not a vault"), Err(CryptoError::UnsupportedFormat));
    /// ```
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut r = Reader(bytes);
        if r.take::<4>()? != *MAGIC {
            return Err(CryptoError::UnsupportedFormat);
        }
        let format = Format::from_version(u16::from_be_bytes(r.take()?))
            .ok_or(CryptoError::UnsupportedFormat)?;
        let header = Self {
            format,
            salt: r.take()?,
            wrap_nonce: r.take()?,
            wrapped_key: r.take()?,
            revision: u64::from_be_bytes(r.take()?),
            body_nonce: r.take()?,
        };
        if !r.0.is_empty() {
            return Err(CryptoError::UnsupportedFormat);
        }
        Ok(header)
    }

    /// Associated data for the vault key wrap: magic, format version (which fixes the
    /// KDF params) and salt, i.e. everything the KEK depends on besides the password.
    ///
    /// ```ignore
    /// let aad = header.wrap_aad();
    /// ```
    pub(crate) fn wrap_aad(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(WRAP_AAD_LEN);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.format.version().to_be_bytes());
        out.extend_from_slice(&self.salt);
        out
    }
}

/// A cursor over untrusted bytes; running out of input is a format error.
struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    /// Takes the next `N` bytes as an array.
    ///
    /// ```ignore
    /// let salt: [u8; 16] = reader.take()?;
    /// ```
    fn take<const N: usize>(&mut self) -> Result<[u8; N], CryptoError> {
        let (head, rest) = self
            .0
            .split_first_chunk()
            .ok_or(CryptoError::UnsupportedFormat)?;
        self.0 = rest;
        Ok(*head)
    }
}
