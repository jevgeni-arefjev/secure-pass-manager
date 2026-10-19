//! `vault` command-line interface. Planned commands: `secure-password-manager.md` §5.
#![forbid(unsafe_code)]

/// Entry point: hardens the process before anything else, then runs the CLI.
///
/// ```text
/// $ vault
/// ```
fn main() {
    if vault_core::crypto::harden_process().is_err() {
        eprintln!("vault: could not disable core dumps; refusing to run");
        std::process::exit(1);
    }
    println!("vault {}: not implemented yet", env!("CARGO_PKG_VERSION"));
}
