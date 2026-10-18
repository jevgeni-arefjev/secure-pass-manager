//! Core logic shared by the CLI (`vault-cli`) and, later, the web server (`vault-web`).
//!
//! Design and threat model: `secure-password-manager.md`.
#![forbid(unsafe_code)]

pub mod audit;
pub mod backup;
pub mod crypto;
pub mod session;
pub mod storage;
