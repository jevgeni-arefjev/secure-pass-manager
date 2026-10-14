//! Encryption module: key derivation, vault key wrap, body encryption/decryption,
//! nonces and salts.
//!
//! The only module that handles plaintext secrets; everything sensitive must be
//! zeroized after use.
//!
//! Algorithms are NOT decided yet. The vault header stores the algorithm ids and
//! parameters, so the choice can change later without breaking old vaults.
//! Candidates (RustCrypto crate in brackets):
//!
//! Password KDF (master password -> KEK):
//! - Argon2id [`argon2`]: memory-hard, current OWASP first choice. Memory cost is
//!   tunable (spec suggests 256 MiB; OWASP minimum is ~19 MiB, t=2, p=1).
//! - scrypt [`scrypt`]: memory-hard, older; harder to tune than Argon2.
//! - PBKDF2-HMAC-SHA256 [`pbkdf2`]: not memory-hard, needs ~600k iterations; low RAM.
//! - bcrypt [`bcrypt`]: named in the course brief, but a password hash, not a KDF
//!   (72-byte input limit, fixed output); would need a separate KDF for the key.
//!
//! Body / key-wrap cipher (AEAD):
//! - XChaCha20-Poly1305 [`chacha20poly1305`]: 192-bit nonce, safe with random nonces;
//!   fast in software.
//! - AES-256-GCM [`aes-gcm`]: fast with AES-NI; 96-bit nonce, so random nonces are
//!   limited per key (fine here, since the vault is rewritten rarely).
//! - AES-256-GCM-SIV [`aes-gcm-siv`]: tolerates nonce reuse; slightly slower.
//!
//! Key wrap: the chosen AEAD over the vault key, or AES-KW (RFC 3394) [`aes-kw`].
//! Subkey derivation (vault key -> body key): HKDF-SHA-256 [`hkdf`].
//! Randomness: OS CSPRNG [`getrandom`].
//! Secret memory: [`zeroize`] / [`secrecy`]; page locking (`mlock`) via e.g. [`memsec`].
