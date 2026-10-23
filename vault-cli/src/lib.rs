//! `vault` command-line front end: the vault shell, its commands, and everything it
//! prints. Planned commands: `secure-password-manager.md` §5. The binary in `main.rs`
//! only hardens the process and calls into here, so tests can drive the CLI through a
//! fake [`terminal::Terminal`].
#![forbid(unsafe_code)]

pub mod render;
pub mod terminal;
