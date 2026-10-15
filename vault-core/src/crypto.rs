//! Encryption module: key derivation, vault key wrap, body encryption/decryption,
//! nonces and salts.
//!
//! The only module that handles plaintext secrets; everything sensitive must be
//! zeroized after use.
//!
//! Crypto functions used (RustCrypto crate in brackets):
//!
//! Password KDF (master password -> KEK):
//! - Argon2id [`argon2`]: memory-hard, current OWASP first choice. m=256 MiB, t=3,
//!   p=1. Params are stored in the vault header, so they can be raised later
//!   without breaking existing vaults.
//!
//! Body / key-wrap cipher (AEAD):
//! - XChaCha20-Poly1305 [`chacha20poly1305`]: 192-bit nonce, safe with random nonces;
//!   fast in software.
//!
//! Key wrap: XChaCha20-Poly1305 over the vault key (same AEAD as the body).
//! Subkey derivation (vault key -> body key): HKDF-SHA-256 [`hkdf`].
//! Randomness: OS CSPRNG [`getrandom`].
//! Secret memory: [`zeroize`]; page locking (`mlock`) via e.g. [`memsec`].
