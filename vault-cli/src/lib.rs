//! `vault` command-line front end: the vault shell, its commands, and everything it
//! prints. Commands: `secure-password-manager.md` §5. The binary in `main.rs` only
//! hardens the process and calls [`shell::run`], so tests can drive the CLI through a
//! fake [`terminal::Terminal`].
#![forbid(unsafe_code)]

pub mod args;
pub mod clipboard;
mod commands;
pub mod render;
pub mod shell;
pub mod terminal;
