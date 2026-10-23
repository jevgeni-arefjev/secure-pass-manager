//! Core logic shared by the CLI (`vault-cli`) and, later, the web server (`vault-web`).
//!
//! Design and threat model: `secure-password-manager.md`.
#![forbid(unsafe_code)]

// Test formats use a cheap KDF (ADR-0005); a release binary must never contain them.
#[cfg(all(feature = "insecure-test-kdf", not(debug_assertions)))]
compile_error!(
    "the `insecure-test-kdf` feature is for tests only and can't be used in release builds"
);

pub mod audit;
pub mod backup;
pub mod crypto;
pub mod generator;
pub mod session;
pub mod storage;
