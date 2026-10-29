//! Encryption module: key derivation, vault key wrap, body encryption/decryption,
//! nonces and salts.
//!
//! Decrypts the body and hands the plaintext to `session`, which owns the secret
//! model; crypto itself never parses secrets. Everything sensitive must be zeroized
//! after use.
//!
//! Crypto functions used (RustCrypto crate in brackets):
//!
//! Password KDF (master password -> KEK):
//! - Argon2id [`argon2`]: memory-hard, current OWASP first choice. m=256 MiB, t=3,
//!   p=1. The params are fixed by the format version in the header (ADR-0005);
//!   raising them means a new format version, and old versions stay readable.
//!
//! Body / key-wrap cipher (AEAD):
//! - XChaCha20-Poly1305 [`chacha20poly1305`]: 192-bit nonce, safe with random nonces;
//!   fast in software.
//!
//! Key wrap: XChaCha20-Poly1305 over the vault key (same AEAD as the body).
//! Subkey derivation (vault key -> body key): HKDF-SHA-256 [`hkdf`].
//! Randomness: OS CSPRNG [`getrandom`].
//! Secret memory: [`zeroize`]; page locking (`mlock`) of key buffers via a crate with a
//! safe API (no `unsafe` calls in this crate).
//!
//! Key hierarchy: master password -(Argon2id)-> KEK, which wraps the random vault key;
//! vault key -(HKDF)-> body key, which encrypts the padded body. The KEK and body key
//! never leave this module. Header layout and associated data: see [`Header`].
//!
//! ```no_run
//! use vault_core::crypto::{self, MasterPassword, Plaintext};
//!
//! let (_, sealed) = crypto::create(
//!     &MasterPassword::new("hunter2".into()),
//!     &Plaintext::new(b"[]".to_vec()),
//! )?;
//! let key = crypto::unlock(&sealed.header, &MasterPassword::new("hunter2".into()))?;
//! assert_eq!(crypto::open_body(&key, &sealed)?.as_bytes(), b"[]");
//! # Ok::<(), crypto::CryptoError>(())
//! ```

mod header;
mod kdf;
mod secret_memory;

use std::fmt;

use chacha20poly1305::aead::inout::InOutBuf;
use chacha20poly1305::{AeadInOut, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;

pub use header::Header;
pub use secret_memory::{MasterPassword, Plaintext, VaultKey};

use header::{Format, NONCE_LEN, SALT_LEN, TAG_LEN};
use kdf::{KEY_LEN, derive_kek};
pub(crate) use secret_memory::LockedBytes;

/// HKDF info for the body key; the version tag lets a future format derive a different key.
const BODY_KEY_INFO: &[u8] = b"secure-pass-manager/v1/body-key";

/// The body plaintext is padded to a multiple of this, hiding the number and size of secrets.
const BODY_PADDING: usize = 4096;

/// Bytes in front of the padded body that record the real plaintext length.
const LENGTH_PREFIX_LEN: usize = 4;

/// Why a crypto operation failed. Messages are fixed strings: they never carry key
/// material, plaintext, or detail an attacker could use.
///
/// ```
/// use vault_core::crypto::CryptoError;
/// assert_eq!(CryptoError::UnlockFailed.to_string(), "unlock failed");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// The vault key didn't unwrap: wrong master password or a tampered header.
    /// The two are deliberately indistinguishable.
    UnlockFailed,
    /// The body failed authentication even though the vault key unwrapped.
    BodyCorrupt,
    /// Unknown format version or KDF, KDF params out of bounds, or malformed bytes.
    UnsupportedFormat,
    /// The OS random number generator failed.
    Randomness,
}

impl fmt::Display for CryptoError {
    /// Writes the fixed, secret-free message for this error.
    ///
    /// ```
    /// # use vault_core::crypto::CryptoError;
    /// assert_eq!(CryptoError::BodyCorrupt.to_string(), "vault body is corrupt");
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnlockFailed => "unlock failed",
            Self::BodyCorrupt => "vault body is corrupt",
            Self::UnsupportedFormat => "unsupported vault format",
            Self::Randomness => "system random number generator failed",
        })
    }
}

impl std::error::Error for CryptoError {}

/// Everything storage persists for one vault: the plaintext header and the
/// encrypted, padded body (ciphertext followed by its tag).
///
/// ```
/// # use vault_core::crypto::{self, MasterPassword, Plaintext};
/// # let password = MasterPassword::new("hunter2".into());
/// # let (_, sealed) = crypto::create_insecure_for_tests(&password, &Plaintext::new(vec![]))?;
/// let (header_bytes, body) = (sealed.header.encode(), &sealed.body); // what storage writes
/// # Ok::<(), crypto::CryptoError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedVault {
    /// Plaintext, authenticated metadata.
    pub header: Header,
    /// The encrypted body.
    pub body: Vec<u8>,
}

/// Creates a new vault in the current format: a random vault key wrapped under
/// `password`, and `plaintext` sealed as revision 0.
///
/// Security: always uses the production KDF params (ADR-0005). The vaultname is not
/// part of the crypto: it is only the file name storage picks (ADR-0004).
///
/// ```no_run
/// # use vault_core::crypto::{self, MasterPassword, Plaintext};
/// let password = MasterPassword::new("hunter2".into());
/// let (key, sealed) = crypto::create(&password, &Plaintext::new(b"[]".to_vec()))?;
/// # Ok::<(), crypto::CryptoError>(())
/// ```
pub fn create(
    password: &MasterPassword,
    plaintext: &Plaintext,
) -> Result<(VaultKey, SealedVault), CryptoError> {
    seal_under_new_key(Format::CURRENT, password, 0, plaintext)
}

/// Like [`create`], but in the test format: OWASP-minimum KDF params, so tests and
/// doctests don't each run a 256 MiB derivation.
///
/// Security: never use for real vaults. Exists only with the `insecure-test-kdf`
/// feature, which only test builds enable and release builds refuse.
///
/// ```
/// # use vault_core::crypto::{self, MasterPassword, Plaintext};
/// let password = MasterPassword::new("hunter2".into());
/// let (key, sealed) = crypto::create_insecure_for_tests(&password, &Plaintext::new(vec![]))?;
/// # Ok::<(), crypto::CryptoError>(())
/// ```
#[cfg(feature = "insecure-test-kdf")]
pub fn create_insecure_for_tests(
    password: &MasterPassword,
    plaintext: &Plaintext,
) -> Result<(VaultKey, SealedVault), CryptoError> {
    seal_under_new_key(Format::V1InsecureTest, password, 0, plaintext)
}

/// Unlocks a vault: derives the KEK from `password` and unwraps the vault key.
///
/// Security: no password hash exists (ADR-0002); a failed tag check is the only
/// signal of a wrong password, reported as [`CryptoError::UnlockFailed`], the same as
/// a tampered header. Every attempt costs a full Argon2id derivation.
///
/// ```
/// # use vault_core::crypto::{self, MasterPassword, Plaintext, CryptoError};
/// # let (_, sealed) = crypto::create_insecure_for_tests(&MasterPassword::new("hunter2".into()), &Plaintext::new(vec![]))?;
/// let wrong = crypto::unlock(&sealed.header, &MasterPassword::new("guess".into()));
/// assert_eq!(wrong.err(), Some(CryptoError::UnlockFailed));
/// # Ok::<(), CryptoError>(())
/// ```
pub fn unlock(header: &Header, password: &MasterPassword) -> Result<VaultKey, CryptoError> {
    let kek = derive_kek(password, header.format.kdf_params(), &header.salt)?;
    let key = aead_open(
        &kek,
        header.wrap_nonce,
        &header.wrap_aad(),
        &header.wrapped_key,
    )
    .ok_or(CryptoError::UnlockFailed)?;
    Ok(VaultKey(key))
}

/// Spends what unlocking a current-format vault costs (one full Argon2id derivation
/// under a random salt) without a vault, and discards the result.
///
/// Security: the session calls this when the vaultname has no vault file, so a missing
/// vault takes as long to refuse as a wrong master password and vaultnames can't be
/// probed by timing.
///
/// ```no_run
/// # use vault_core::crypto::{self, MasterPassword};
/// crypto::simulate_unlock(&MasterPassword::new("guess".into()))?;
/// # Ok::<(), crypto::CryptoError>(())
/// ```
pub fn simulate_unlock(password: &MasterPassword) -> Result<(), CryptoError> {
    let salt: [u8; SALT_LEN] = random_array()?;
    derive_kek(password, Format::CURRENT.kdf_params(), &salt).map(drop)
}

/// Decrypts a vault body with an unlocked vault key, straight into locked memory.
///
/// Security: authenticates the whole header as associated data, so any header or body
/// change gives [`CryptoError::BodyCorrupt`] and no plaintext.
///
/// ```
/// # use vault_core::crypto::{self, MasterPassword, Plaintext};
/// # let password = MasterPassword::new("hunter2".into());
/// # let (key, sealed) = crypto::create_insecure_for_tests(&password, &Plaintext::new(b"[]".to_vec()))?;
/// assert_eq!(crypto::open_body(&key, &sealed)?.as_bytes(), b"[]");
/// # Ok::<(), crypto::CryptoError>(())
/// ```
pub fn open_body(key: &VaultKey, sealed: &SealedVault) -> Result<Plaintext, CryptoError> {
    let ciphertext_len = sealed.body.len().saturating_sub(TAG_LEN);
    if ciphertext_len == 0 || !ciphertext_len.is_multiple_of(BODY_PADDING) {
        return Err(CryptoError::BodyCorrupt);
    }
    let header = &sealed.header;
    let padded = aead_open(
        &body_key(key),
        header.body_nonce,
        &header.encode(),
        &sealed.body,
    )
    .ok_or(CryptoError::BodyCorrupt)?;
    let (prefix, rest) = padded.as_bytes().split_at(LENGTH_PREFIX_LEN);
    let len = usize::try_from(u32::from_be_bytes(
        prefix.try_into().expect("4-byte prefix"),
    ))
    .map_err(|_| CryptoError::BodyCorrupt)?;
    let data = rest.get(..len).ok_or(CryptoError::BodyCorrupt)?;
    Ok(Plaintext(LockedBytes::from_slice(data)))
}

/// Saves a new version of the body: same vault key, fresh body nonce, revision + 1.
///
/// Security: `key` must be the key unlocked from `header`'s vault. Sealing with
/// another key writes a body that will never decrypt, so the session should only ever
/// pass the key it unlocked (or got back from [`change_master_password`]).
///
/// ```
/// # use vault_core::crypto::{self, MasterPassword, Plaintext};
/// # let password = MasterPassword::new("hunter2".into());
/// # let (key, v0) = crypto::create_insecure_for_tests(&password, &Plaintext::new(b"[]".to_vec()))?;
/// let v1 = crypto::seal(&key, &v0.header, &Plaintext::new(br#"[{"title":"github"}]"#.to_vec()))?;
/// assert_eq!(v1.header.revision(), 1);
/// # Ok::<(), crypto::CryptoError>(())
/// ```
pub fn seal(
    key: &VaultKey,
    header: &Header,
    plaintext: &Plaintext,
) -> Result<SealedVault, CryptoError> {
    let mut next = header.clone();
    next.revision = next_revision(header)?;
    seal_body(key, next, plaintext)
}

/// Changes the master password. Always rotates the vault key: a new random vault key
/// re-encrypts `plaintext` and is wrapped under a KEK derived from `new` with a fresh
/// salt, so a pre-change copy of the vault never decrypts later versions. The vault
/// keeps its format version.
///
/// Security: `current` is verified first (one Argon2id run), giving
/// [`CryptoError::UnlockFailed`] if wrong. Callers must replace their held vault key
/// with the returned one; the old key can no longer open the vault.
///
/// ```
/// # use vault_core::crypto::{self, MasterPassword, Plaintext};
/// # let old = MasterPassword::new("hunter2".into());
/// # let (_, sealed) = crypto::create_insecure_for_tests(&old, &Plaintext::new(vec![]))?;
/// let new = MasterPassword::new("correct horse battery staple".into());
/// let (key, sealed) =
///     crypto::change_master_password(&sealed.header, &old, &new, &Plaintext::new(vec![]))?;
/// # Ok::<(), crypto::CryptoError>(())
/// ```
pub fn change_master_password(
    header: &Header,
    current: &MasterPassword,
    new: &MasterPassword,
    plaintext: &Plaintext,
) -> Result<(VaultKey, SealedVault), CryptoError> {
    unlock(header, current)?;
    seal_under_new_key(header.format, new, next_revision(header)?, plaintext)
}

/// Generates a random vault key, wraps it under `password` in `format`, and seals
/// `plaintext` at `revision`. Shared by create and password change.
///
/// ```ignore
/// let (key, sealed) = seal_under_new_key(Format::CURRENT, &password, 0, &plaintext)?;
/// ```
fn seal_under_new_key(
    format: Format,
    password: &MasterPassword,
    revision: u64,
    plaintext: &Plaintext,
) -> Result<(VaultKey, SealedVault), CryptoError> {
    let mut key = LockedBytes::zeroed(KEY_LEN);
    fill_random(key.as_mut_bytes())?;
    let key = VaultKey(key);
    let header = wrap_vault_key(&key, format, password, revision)?;
    let sealed = seal_body(&key, header, plaintext)?;
    Ok((key, sealed))
}

/// The revision the next save of `header`'s vault gets.
///
/// ```ignore
/// next.revision = next_revision(&header)?;
/// ```
fn next_revision(header: &Header) -> Result<u64, CryptoError> {
    header
        .revision
        .checked_add(1)
        .ok_or(CryptoError::UnsupportedFormat)
}

/// Process-wide memory hardening; call it first thing in `main`, before any secret
/// exists. Disables core dumps (`RLIMIT_CORE` = 0) so a crash can't write keys or
/// decrypted secrets to disk. No-op on non-Unix platforms.
///
/// ```
/// vault_core::crypto::harden_process().expect("could not disable core dumps");
/// ```
pub fn harden_process() -> std::io::Result<()> {
    #[cfg(unix)]
    rlimit::setrlimit(rlimit::Resource::CORE, 0, 0)?;
    Ok(())
}

/// Builds a `format` header whose wrapped key is `key` under a KEK derived from
/// `password` with a fresh salt and wrap nonce. The body nonce is left for [`seal_body`].
///
/// ```ignore
/// let header = wrap_vault_key(&key, Format::CURRENT, &password, 0)?;
/// ```
fn wrap_vault_key(
    key: &VaultKey,
    format: Format,
    password: &MasterPassword,
    revision: u64,
) -> Result<Header, CryptoError> {
    let mut header = Header {
        format,
        salt: random_array()?,
        wrap_nonce: random_array()?,
        wrapped_key: [0; KEY_LEN + TAG_LEN],
        revision,
        body_nonce: [0; NONCE_LEN],
    };
    let kek = derive_kek(password, format.kdf_params(), &header.salt)?;
    let aad = header.wrap_aad();
    aead_seal(
        &kek,
        header.wrap_nonce,
        &aad,
        key.0.as_bytes(),
        &mut header.wrapped_key,
    );
    Ok(header)
}

/// Seals `plaintext` under `header` with a fresh body nonce: pads it to a multiple of
/// [`BODY_PADDING`] in locked memory, then encrypts with the whole header as associated data.
///
/// ```ignore
/// let sealed = seal_body(&key, header, &plaintext)?;
/// ```
fn seal_body(
    key: &VaultKey,
    mut header: Header,
    plaintext: &Plaintext,
) -> Result<SealedVault, CryptoError> {
    header.body_nonce = random_array()?;
    let data = plaintext.as_bytes();
    let len = u32::try_from(data.len()).map_err(|_| CryptoError::UnsupportedFormat)?;
    let padded_len = (LENGTH_PREFIX_LEN + data.len()).div_ceil(BODY_PADDING) * BODY_PADDING;
    let mut padded = LockedBytes::zeroed(padded_len);
    let (prefix, rest) = padded.as_mut_bytes().split_at_mut(LENGTH_PREFIX_LEN);
    prefix.copy_from_slice(&len.to_be_bytes());
    rest[..data.len()].copy_from_slice(data);

    let mut body = vec![0; padded_len + TAG_LEN];
    aead_seal(
        &body_key(key),
        header.body_nonce,
        &header.encode(),
        padded.as_bytes(),
        &mut body,
    );
    Ok(SealedVault { header, body })
}

/// Derives the body key from the vault key with HKDF-SHA-256 into locked memory.
///
/// ```ignore
/// let body_key = body_key(&vault_key);
/// ```
fn body_key(key: &VaultKey) -> LockedBytes {
    let mut out = LockedBytes::zeroed(KEY_LEN);
    Hkdf::<Sha256>::new(None, key.0.as_bytes())
        .expand(BODY_KEY_INFO, out.as_mut_bytes())
        .expect("32 bytes is a valid HKDF-SHA-256 output length");
    out
}

/// Encrypts `plaintext` with XChaCha20-Poly1305 into `out`, which must be exactly
/// `plaintext.len() + TAG_LEN` bytes: ciphertext followed by the tag. The plaintext is
/// read from its (locked) buffer directly; it is never copied into `out` unencrypted.
///
/// ```ignore
/// let mut body = vec![0; padded.len() + TAG_LEN];
/// aead_seal(&body_key, nonce, &header.encode(), padded.as_bytes(), &mut body);
/// ```
fn aead_seal(
    key: &LockedBytes,
    nonce: [u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) {
    let (ciphertext, tag_out) = out.split_at_mut(plaintext.len());
    let buffer = InOutBuf::new(plaintext, ciphertext).expect("output sized to plaintext + tag");
    let tag = cipher(key)
        .encrypt_inout_detached(&XNonce::from(nonce), aad, buffer)
        .expect("vault plaintexts are far below the XChaCha20 message limit");
    tag_out.copy_from_slice(&tag);
}

/// Authenticates and decrypts `sealed` (ciphertext followed by its tag) straight into
/// locked memory. `None` on any tag failure or if `sealed` is shorter than a tag;
/// callers map that to their own error.
///
/// ```ignore
/// let key = aead_open(&kek, header.wrap_nonce, &header.wrap_aad(), &header.wrapped_key)
///     .ok_or(CryptoError::UnlockFailed)?;
/// ```
fn aead_open(
    key: &LockedBytes,
    nonce: [u8; NONCE_LEN],
    aad: &[u8],
    sealed: &[u8],
) -> Option<LockedBytes> {
    let (ciphertext, tag) = sealed.split_at_checked(sealed.len().checked_sub(TAG_LEN)?)?;
    let mut out = LockedBytes::zeroed(ciphertext.len());
    let buffer = InOutBuf::new(ciphertext, out.as_mut_bytes()).expect("output sized to ciphertext");
    let tag = Tag::try_from(tag).expect("split off exactly TAG_LEN bytes");
    cipher(key)
        .decrypt_inout_detached(&XNonce::from(nonce), aad, buffer, &tag)
        .ok()?;
    Some(out)
}

/// XChaCha20-Poly1305 keyed with a 32-byte key. The cipher zeroizes its key copy on drop.
///
/// ```ignore
/// let cipher = cipher(&kek);
/// ```
fn cipher(key: &LockedBytes) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new_from_slice(key.as_bytes()).expect("keys are always 32 bytes")
}

/// Fills `out` from the OS CSPRNG.
///
/// ```ignore
/// fill_random(key.as_mut_bytes())?;
/// ```
fn fill_random(out: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(out).map_err(|_| CryptoError::Randomness)
}

/// A fresh random array from the OS CSPRNG, for salts and nonces (not keys: those go
/// straight into locked memory via [`fill_random`]).
///
/// ```ignore
/// let nonce: [u8; 24] = random_array()?;
/// ```
fn random_array<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut out = [0; N];
    fill_random(&mut out)?;
    Ok(out)
}
