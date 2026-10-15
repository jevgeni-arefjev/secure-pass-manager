//! Encryption module: key derivation, vault key wrap, body encryption/decryption,
//! nonces and salts.
//!
//! The only module that handles plaintext secrets; everything sensitive must be
//! zeroized after use.
//!
//! Crypto functions used (RustCrypto crate in brackets):
//!
//! Password KDF (master password -> KEK):
//! - Argon2id [`argon2`]: memory-hard, current OWASP first choice. Memory cost is
//!   tunable (spec suggests 256 MiB; OWASP minimum is ~19 MiB, t=2, p=1).
//!
//! Body / key-wrap cipher (AEAD):
//! - XChaCha20-Poly1305 [`chacha20poly1305`]: 192-bit nonce, safe with random nonces;
//!   fast in software.
//!
//! Key wrap: the chosen AEAD over the vault key, or AES-KW (RFC 3394) [`aes-kw`].
//! Subkey derivation (vault key -> body key): HKDF-SHA-256 [`hkdf`].
//! Randomness: OS CSPRNG [`getrandom`].
//! Secret memory: [`zeroize`] / [`secrecy`]; page locking (`mlock`) via e.g. [`memsec`].
