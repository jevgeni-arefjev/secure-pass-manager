//! Password KDF: Argon2id turns the master password into the KEK.

use argon2::{Algorithm, Argon2, Params, Version};

use super::CryptoError;
use super::secret_memory::{LockedBytes, MasterPassword};

/// Length of the KEK and of every symmetric key in the vault, in bytes.
pub(crate) const KEY_LEN: usize = 32;

/// Argon2id cost parameters. Never read from a header: each format version maps to
/// one fixed set (ADR-0005), so there is nothing to bounds-check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KdfParams {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

impl KdfParams {
    /// Format version 1: 256 MiB, t=3, p=1.
    pub(crate) const V1: Self = Self {
        memory_kib: 256 * 1024,
        iterations: 3,
        parallelism: 1,
    };

    /// Test formats only: OWASP's minimum (19 MiB, t=2, p=1), so tests stay fast.
    ///
    /// Security: compiled only with the `insecure-test-kdf` feature, which release
    /// builds refuse (see `lib.rs`).
    #[cfg(feature = "insecure-test-kdf")]
    pub(crate) const INSECURE_TEST: Self = Self {
        memory_kib: 19 * 1024,
        iterations: 2,
        parallelism: 1,
    };
}

/// Derives the KEK from the master password with Argon2id, straight into locked memory.
///
/// Security: costs a full Argon2id run whether or not the password is right, which is
/// what makes guessing expensive. Argon2's working memory is zeroized by the crate.
///
/// ```ignore
/// let kek = derive_kek(&password, header.format.kdf_params(), &header.salt)?;
/// ```
pub(crate) fn derive_kek(
    password: &MasterPassword,
    params: KdfParams,
    salt: &[u8],
) -> Result<LockedBytes, CryptoError> {
    let params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .expect("fixed params are valid Argon2 params");
    let mut kek = LockedBytes::zeroed(KEY_LEN);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, kek.as_mut_bytes())
        .map_err(|_| CryptoError::UnsupportedFormat)?;
    Ok(kek)
}
